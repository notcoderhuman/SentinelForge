"use strict";
(function (root, factory) {
  const helpers = factory();
  if (typeof module === "object" && module.exports) module.exports = helpers;
  if (root) root.SentinelForgeHelpers = helpers;
}(typeof globalThis === "object" ? globalThis : this, function () {
  const INCIDENT_TRANSITIONS = Object.freeze({
    open: Object.freeze(["investigating", "resolved"]),
    investigating: Object.freeze(["resolved"]),
    resolved: Object.freeze(["closed"]),
    closed: Object.freeze([])
  });
  const ERROR_MESSAGES = Object.freeze({
    401: "Session/authentication required.",
    403: "You are not permitted to perform that request.",
    404: "The case no longer exists.",
    409: "The case state changed or that transition is invalid.",
    413: "The note or request body is too large.",
    500: "The server encountered an internal error.",
    503: "The database is temporarily unavailable."
  });
  function nextIncidentStatuses(status) { return (INCIDENT_TRANSITIONS[status] || []).slice(); }
  function nextInvestigationStatuses(status) { return status === "active" ? ["completed"] : []; }
  function utf8ByteLength(value) { return new TextEncoder().encode(String(value)).length; }
  function validateNoteContent(value, limit) {
    const bytes = utf8ByteLength(value);
    const max = limit || 16 * 1024;
    return { bytes, max, valid: bytes <= max && String(value).trim().length > 0 };
  }
  function queryString(values) {
    const params = new URLSearchParams();
    Object.entries(values || {}).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== "") params.set(key, value);
    });
    const query = params.toString();
    return query ? `?${query}` : "";
  }
  function errorMessage(status) { return ERROR_MESSAGES[status] || "The request could not be completed."; }
  return { nextIncidentStatuses, nextInvestigationStatuses, utf8ByteLength, validateNoteContent, queryString, errorMessage };
}));
