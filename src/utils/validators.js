function requiredString(value, fieldName) {
  if (typeof value !== 'string' || value.trim().length === 0) {
    const err = new Error(`${fieldName} is required`);
    err.status = 400;
    throw err;
  }

  return value.trim();
}

module.exports = {
  requiredString,
};