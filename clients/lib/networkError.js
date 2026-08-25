'use strict';

function compact(value) {
  return String(value || '').replace(/\s+/g, ' ').trim();
}

function describeNetworkError(error) {
  const descriptions = [];
  const seenObjects = new Set();
  const seenDescriptions = new Set();

  function add(value) {
    const description = compact(value);
    if (!description || seenDescriptions.has(description)) return;
    seenDescriptions.add(description);
    descriptions.push(description);
  }

  function visit(current) {
    if (current == null) return;
    if (typeof current !== 'object') {
      add(current);
      return;
    }
    if (seenObjects.has(current)) return;
    seenObjects.add(current);

    const message = compact(current.message);
    const endpoint = current.address
      ? `${current.address}${current.port ? `:${current.port}` : ''}`
      : current.port ? `port ${current.port}` : '';
    const fields = [];
    if (current.name && current.name !== 'Error' && current.name !== 'AggregateError') fields.push(current.name);
    if (current.code && !message.includes(String(current.code))) fields.push(current.code);
    if (current.syscall && !message.includes(String(current.syscall))) fields.push(current.syscall);
    if (message) fields.push(message);
    if (endpoint && !message.includes(endpoint)) fields.push(endpoint);
    if (!fields.length && current.name) fields.push(current.name);
    add(fields.join(' '));

    if (Array.isArray(current.errors)) current.errors.forEach(visit);
    if (current.cause) visit(current.cause);
  }

  visit(error);
  return descriptions.join(' | ') || 'Unknown network error';
}

module.exports = { describeNetworkError };
