import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import process from "node:process";
import tls from "node:tls";
import vm from "node:vm";

const DEFAULT_LOADER_URL = "https://sentinel.openai.com/backend-api/sentinel/sdk.js";
const SENTINEL_BASE = "https://sentinel.openai.com";
const AUTH_BASE = "https://auth.openai.com";

function btoaCompat(value) {
  return Buffer.from(String(value), "binary").toString("base64");
}

function atobCompat(value) {
  return Buffer.from(String(value), "base64").toString("binary");
}

function originOf(value) {
  try {
    return new URL(value).origin;
  } catch {
    return AUTH_BASE;
  }
}

async function fetchText(url, headers) {
  const response = await fetch(url, { headers });
  if (!response.ok) {
    throw new Error(`fetch_${response.status}_${url}`);
  }
  return response.text();
}

function proxyAuthHeader(proxyURL) {
  if (!proxyURL.username && !proxyURL.password) {
    return {};
  }
  const raw = `${decodeURIComponent(proxyURL.username)}:${decodeURIComponent(proxyURL.password)}`;
  return { "Proxy-Authorization": `Basic ${Buffer.from(raw).toString("base64")}` };
}

function collectResponse(response, resolve, reject) {
  const chunks = [];
  response.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
  response.on("end", () => {
    resolve(
      new Response(Buffer.concat(chunks), {
        status: response.statusCode || 0,
        headers: response.headers,
      }),
    );
  });
  response.on("error", reject);
}

function requestDirect(target, options) {
  return new Promise((resolve, reject) => {
    const transport = target.protocol === "http:" ? http : https;
    const request = transport.request(
      {
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port || (target.protocol === "http:" ? 80 : 443),
        path: `${target.pathname}${target.search}`,
        method: options.method || "GET",
        headers: options.headers,
      },
      (response) => collectResponse(response, resolve, reject),
    );
    request.on("error", reject);
    if (options.body) {
      request.write(options.body);
    }
    request.end();
  });
}

function requestViaHTTPProxy(target, proxyURL, options) {
  if (target.protocol === "http:") {
    return new Promise((resolve, reject) => {
      const request = http.request(
        {
          hostname: proxyURL.hostname,
          port: proxyURL.port || 80,
          path: target.href,
          method: options.method || "GET",
          headers: {
            Host: target.host,
            ...proxyAuthHeader(proxyURL),
            ...options.headers,
          },
        },
        (response) => collectResponse(response, resolve, reject),
      );
      request.on("error", reject);
      if (options.body) {
        request.write(options.body);
      }
      request.end();
    });
  }
  if (target.protocol !== "https:") {
    return requestDirect(target, options);
  }
  return new Promise((resolve, reject) => {
    const connect = http.request({
      hostname: proxyURL.hostname,
      port: proxyURL.port || 80,
      method: "CONNECT",
      path: `${target.hostname}:${target.port || 443}`,
      headers: {
        Host: `${target.hostname}:${target.port || 443}`,
        ...proxyAuthHeader(proxyURL),
      },
    });
    connect.on("connect", (response, socket) => {
      if ((response.statusCode || 0) < 200 || (response.statusCode || 0) >= 300) {
        socket.destroy();
        reject(new Error(`proxy_connect_${response.statusCode || 0}`));
        return;
      }
      const tlsSocket = tls.connect({
        socket,
        servername: target.hostname,
      });
      tlsSocket.on("secureConnect", () => {
        const request = https.request(
          {
            hostname: target.hostname,
            port: target.port || 443,
            path: `${target.pathname}${target.search}`,
            method: options.method || "GET",
            headers: options.headers,
            createConnection: () => tlsSocket,
            agent: false,
          },
          (innerResponse) => collectResponse(innerResponse, resolve, reject),
        );
        request.on("error", reject);
        if (options.body) {
          request.write(options.body);
        }
        request.end();
      });
      tlsSocket.on("error", reject);
    });
    connect.on("error", reject);
    connect.end();
  });
}

function readExact(socket, length) {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    const onData = (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length >= length) {
        cleanup();
        const head = buffer.subarray(0, length);
        const rest = buffer.subarray(length);
        if (rest.length) {
          socket.unshift(rest);
        }
        resolve(head);
      }
    };
    const onError = (error) => {
      cleanup();
      reject(error);
    };
    const cleanup = () => {
      socket.off("data", onData);
      socket.off("error", onError);
    };
    socket.on("data", onData);
    socket.on("error", onError);
  });
}

function socketWrite(socket, data) {
  return new Promise((resolve, reject) => {
    socket.write(data, (error) => (error ? reject(error) : resolve()));
  });
}

async function connectSocks5(proxyURL, target) {
  const socket = net.connect(Number(proxyURL.port || 1080), proxyURL.hostname);
  await new Promise((resolve, reject) => {
    socket.once("connect", resolve);
    socket.once("error", reject);
  });
  const username = decodeURIComponent(proxyURL.username || "");
  const password = decodeURIComponent(proxyURL.password || "");
  const methods = username || password ? Buffer.from([0x05, 0x01, 0x02]) : Buffer.from([0x05, 0x01, 0x00]);
  await socketWrite(socket, methods);
  const methodResponse = await readExact(socket, 2);
  if (methodResponse[0] !== 0x05 || methodResponse[1] === 0xff) {
    socket.destroy();
    throw new Error("socks5_method_rejected");
  }
  if (methodResponse[1] === 0x02) {
    const user = Buffer.from(username);
    const pass = Buffer.from(password);
    if (user.length > 255 || pass.length > 255) {
      socket.destroy();
      throw new Error("socks5_auth_too_long");
    }
    await socketWrite(socket, Buffer.concat([Buffer.from([0x01, user.length]), user, Buffer.from([pass.length]), pass]));
    const authResponse = await readExact(socket, 2);
    if (authResponse[1] !== 0x00) {
      socket.destroy();
      throw new Error("socks5_auth_failed");
    }
  }
  const host = Buffer.from(target.hostname);
  if (host.length > 255) {
    socket.destroy();
    throw new Error("socks5_host_too_long");
  }
  const port = Number(target.port || (target.protocol === "http:" ? 80 : 443));
  const portBuffer = Buffer.alloc(2);
  portBuffer.writeUInt16BE(port);
  await socketWrite(socket, Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x03, host.length]), host, portBuffer]));
  const head = await readExact(socket, 4);
  if (head[1] !== 0x00) {
    socket.destroy();
    throw new Error(`socks5_connect_${head[1]}`);
  }
  if (head[3] === 0x01) {
    await readExact(socket, 4);
  } else if (head[3] === 0x03) {
    const length = (await readExact(socket, 1))[0];
    await readExact(socket, length);
  } else if (head[3] === 0x04) {
    await readExact(socket, 16);
  }
  await readExact(socket, 2);
  return socket;
}

async function requestViaSocks5(target, proxyURL, options) {
  const socket = await connectSocks5(proxyURL, target);
  const isHTTPS = target.protocol === "https:";
  const connection = isHTTPS
    ? tls.connect({ socket, servername: target.hostname })
    : socket;
  if (isHTTPS) {
    await new Promise((resolve, reject) => {
      connection.once("secureConnect", resolve);
      connection.once("error", reject);
    });
  }
  return new Promise((resolve, reject) => {
    const transport = isHTTPS ? https : http;
    const request = transport.request(
      {
        hostname: target.hostname,
        port: target.port || (isHTTPS ? 443 : 80),
        path: `${target.pathname}${target.search}`,
        method: options.method || "GET",
        headers: options.headers,
        createConnection: () => connection,
        agent: false,
      },
      (response) => collectResponse(response, resolve, reject),
    );
    request.on("error", reject);
    if (options.body) {
      request.write(options.body);
    }
    request.end();
  });
}

function normalizeProxy(raw) {
  const value = String(raw || "").trim();
  if (!value) {
    return null;
  }
  const proxyURL = new URL(value);
  if (!["http:", "socks5:", "socks5h:"].includes(proxyURL.protocol)) {
    throw new Error(`unsupported_proxy_protocol_${proxyURL.protocol.replace(":", "")}`);
  }
  return proxyURL;
}

function makeFetch(proxyURL) {
  return async (url, options = {}) => {
    const target = new URL(url);
    const headers = { ...(options.headers || {}) };
    const body = options.body == null ? null : Buffer.from(String(options.body));
    if (body && !Object.keys(headers).some((key) => key.toLowerCase() === "content-length")) {
      headers["content-length"] = String(body.length);
    }
    const normalized = { method: options.method || "GET", headers, body };
    if (!proxyURL) {
      return requestDirect(target, normalized);
    }
    if (proxyURL.protocol === "socks5:" || proxyURL.protocol === "socks5h:") {
      return requestViaSocks5(target, proxyURL, normalized);
    }
    return requestViaHTTPProxy(target, proxyURL, normalized);
  };
}

function makeDocument({ href, sdkUrl, deviceId }) {
  const listeners = new Map();
  const script = { src: sdkUrl };
  let cookie = `oai-did=${encodeURIComponent(deviceId)}`;
  const documentElement = {
    getAttribute(name) {
      return name === "data-build" ? "" : null;
    },
  };
  const document = {
    currentScript: script,
    scripts: [script],
    documentElement,
    cookie,
    head: null,
    body: null,
    createElement(tagName) {
      const tag = String(tagName || "").toLowerCase();
      const elementListeners = new Map();
      const element = {
        tagName: tag.toUpperCase(),
        style: {},
        async: false,
        defer: false,
        type: "",
        src: "",
        addEventListener(type, handler) {
          const items = elementListeners.get(type) || [];
          items.push(handler);
          elementListeners.set(type, items);
        },
        __dispatch(type) {
          for (const handler of elementListeners.get(type) || []) {
            handler.call(element, { type, target: element });
          }
        },
      };
      return element;
    },
    addEventListener(type, handler) {
      const items = listeners.get(type) || [];
      items.push(handler);
      listeners.set(type, items);
    },
    __dispatch(type, event) {
      for (const handler of listeners.get(type) || []) {
        handler.call(document, event);
      }
    },
  };
  const appendChild = (element) => {
    setTimeout(() => {
      if (typeof element.__dispatch === "function") {
        element.__dispatch("load");
      }
    }, 0);
    return element;
  };
  document.head = { appendChild };
  document.body = { appendChild };
  Object.defineProperty(document, "location", {
    get() {
      return new URL(href);
    },
  });
  Object.defineProperty(document, "cookie", {
    get() {
      return cookie;
    },
    set(value) {
      const next = String(value || "").split(";", 1)[0];
      if (!next) {
        return;
      }
      const [name] = next.split("=", 1);
      const parts = cookie ? cookie.split(/;\s*/) : [];
      const filtered = parts.filter((item) => item.split("=", 1)[0] !== name);
      filtered.push(next);
      cookie = filtered.join("; ");
    },
  });
  return document;
}

function makeWindow({ href, sdkUrl, deviceId, userAgent, fetchImpl }) {
  const listeners = new Map();
  const window = {
    console,
    URL,
    URLSearchParams,
    TextEncoder,
    setTimeout,
    clearTimeout,
    Promise,
    Math,
    Date,
    JSON,
    Array,
    Object,
    Number,
    String,
    Boolean,
    RegExp,
    Error,
    Map,
    WeakMap,
    Uint8Array,
    Buffer,
    btoa: btoaCompat,
    atob: atobCompat,
    crypto: crypto.webcrypto,
    fetch: fetchImpl,
    location: new URL(href),
    origin: originOf(href),
    screen: { width: 1920, height: 1080 },
    performance: {
      timeOrigin: Date.now() - Math.random() * 50000,
      memory: { jsHeapSizeLimit: 4294705152 },
      now() {
        return Date.now() - this.timeOrigin;
      },
    },
    navigator: {
      userAgent,
      language: "en-US",
      languages: ["en-US", "en", "es-US", "es"],
      hardwareConcurrency: 8,
      cookieEnabled: true,
      doNotTrack: null,
      onLine: true,
      pdfViewerEnabled: true,
      plugins: [],
      mimeTypes: [],
    },
    addEventListener(type, handler) {
      const items = listeners.get(type) || [];
      items.push(handler);
      listeners.set(type, items);
    },
    removeEventListener(type, handler) {
      const items = listeners.get(type) || [];
      listeners.set(
        type,
        items.filter((item) => item !== handler),
      );
    },
    __dispatchMessage(data, source, origin) {
      const event = { data, source, origin };
      for (const handler of listeners.get("message") || []) {
        handler.call(window, event);
      }
    },
  };
  window.window = window;
  window.self = window;
  window.globalThis = window;
  window.document = makeDocument({ href, sdkUrl, deviceId });
  window.requestIdleCallback = (callback) =>
    setTimeout(() => callback({ timeRemaining: () => 10, didTimeout: false }), 0);
  window.cancelIdleCallback = (id) => clearTimeout(id);
  window.postMessage = (data) => {
    window.__dispatchMessage(data, window, window.origin);
  };
  return window;
}

function wireIframe(parentWindow, frameWindow, frameUrl) {
  const contentWindow = {
    postMessage(data) {
      frameWindow.__dispatchMessage(data, parentWindow, parentWindow.origin);
    },
  };
  const iframe = {
    style: {},
    src: frameUrl,
    contentWindow,
    addEventListener(type, handler) {
      if (type === "load") {
        setTimeout(() => handler.call(iframe, { type: "load", target: iframe }), 0);
      }
    },
  };
  parentWindow.document.createElement = (tagName) => {
    if (String(tagName || "").toLowerCase() === "iframe") {
      return iframe;
    }
    return makeDocument({
      href: parentWindow.location.href,
      sdkUrl: parentWindow.document.currentScript.src,
      deviceId: "",
    }).createElement(tagName);
  };
  parentWindow.postMessage = (data) => {
    parentWindow.__dispatchMessage(data, contentWindow, frameWindow.origin);
  };
  frameWindow.parent = parentWindow;
  frameWindow.top = parentWindow;
}

function runSDK(source, window) {
  const context = vm.createContext(window);
  vm.runInContext(source, context, { timeout: 5000 });
  return context;
}

async function main() {
  const input = JSON.parse(fs.readFileSync(0, "utf8") || "{}");
  const flow = String(input.flow || "oauth_create_account");
  const deviceId = String(input.device_id || crypto.randomUUID());
  const userAgent = String(
    input.user_agent ||
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
  );
  const secCHUA = String(
    input.sec_ch_ua || '"Google Chrome";v="145", "Not?A_Brand";v="8", "Chromium";v="145"',
  );
  const needSO = Boolean(input.need_so);
  const loaderUrl = String(input.loader_url || DEFAULT_LOADER_URL);
  const proxyURL = normalizeProxy(input.proxy || process.env.HTTPS_PROXY || process.env.HTTP_PROXY || "");
  const pageUrl = String(input.page_url || "").trim();
  const sdkFetch = makeFetch(proxyURL);
  const commonHeaders = {
    "user-agent": userAgent,
    "sec-ch-ua": secCHUA,
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
  };

  globalThis.fetch = sdkFetch;
  const loader = await fetchText(loaderUrl, commonHeaders);
  const sdkUrl = loader.match(/https:\/\/sentinel\.openai\.com\/sentinel\/[^'"]+\/sdk\.js/)?.[0];
  if (!sdkUrl) {
    throw new Error("sentinel_sdk_url_not_found");
  }
  const sdkVersion = sdkUrl.match(/\/sentinel\/([^/]+)\/sdk\.js$/)?.[1] || "";
  const sdkSource = await fetchText(sdkUrl, commonHeaders);
  const frameUrl = `${SENTINEL_BASE}/backend-api/sentinel/frame.html?sv=${encodeURIComponent(sdkVersion)}`;
  const parentUrl = pageUrl
    ? (pageUrl.startsWith("http") ? pageUrl : `${AUTH_BASE}${pageUrl.startsWith("/") ? "" : "/"}${pageUrl}`)
    : `${AUTH_BASE}/create-account?device_id=${encodeURIComponent(deviceId)}&flow=&screen_hint=login_or_signup`;

  const frameFetch = (url, options = {}) =>
    fetch(url, {
      ...options,
      headers: {
        "content-type": "text/plain;charset=UTF-8",
        referer: frameUrl,
        origin: SENTINEL_BASE,
        ...commonHeaders,
        ...(options.headers || {}),
      },
    });

  const parentWindow = makeWindow({
    href: parentUrl,
    sdkUrl,
    deviceId,
    userAgent,
    fetchImpl: sdkFetch,
  });
  const frameWindow = makeWindow({
    href: frameUrl,
    sdkUrl,
    deviceId,
    userAgent,
    fetchImpl: frameFetch,
  });
  parentWindow.top = parentWindow;
  parentWindow.parent = parentWindow;
  wireIframe(parentWindow, frameWindow, frameUrl);

  runSDK(sdkSource, frameWindow);
  runSDK(sdkSource, parentWindow);

  const token = await parentWindow.SentinelSDK.token(flow);
  let soToken = "";
  if (needSO && typeof parentWindow.SentinelSDK.sessionObserverToken === "function") {
    await new Promise((resolve) => setTimeout(resolve, 5000));
    soToken = (await parentWindow.SentinelSDK.sessionObserverToken(flow)) || "";
  }

  process.stdout.write(
    JSON.stringify({
      token,
      so_token: soToken,
      sdk_url: sdkUrl,
      sdk_version: sdkVersion,
      token_len: token ? token.length : 0,
      so_token_len: soToken ? soToken.length : 0,
      has_so_token: Boolean(soToken),
    }),
  );
}

try {
  await main();
} catch (error) {
  process.stderr.write(String(error?.stack || error?.message || error));
  process.exit(1);
}
