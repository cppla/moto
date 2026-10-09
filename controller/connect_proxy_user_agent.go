package controller

// Upstream CONNECT requests use the fixed identity matching the built-in
// Chrome transport template, independent of inbound client request headers.
const connectProxyChromeUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
