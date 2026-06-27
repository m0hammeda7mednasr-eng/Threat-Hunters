const EGYPT_TIME_ZONE = 'Africa/Cairo';
const DEFAULT_LOCALE = 'en-US';

const toDate = (value) => {
  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? null : value;
  }

  if (typeof value === 'number') {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : date;
  }

  if (typeof value === 'string' && value.trim()) {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : date;
  }

  return null;
};

const formatWithOptions = (value, options) => {
  const date = toDate(value) ?? new Date();
  return new Intl.DateTimeFormat(DEFAULT_LOCALE, options).format(date);
};

export const formatEgyptDate = (value, options = {}) =>
  formatWithOptions(value, {
    timeZone: EGYPT_TIME_ZONE,
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    ...options,
  });

export const formatEgyptTime = (value, options = {}) =>
  formatWithOptions(value, {
    timeZone: EGYPT_TIME_ZONE,
    hour: 'numeric',
    minute: '2-digit',
    hour12: true,
    ...options,
  });

export const formatEgyptDateTime = (value, options = {}) =>
  formatWithOptions(value, {
    timeZone: EGYPT_TIME_ZONE,
    dateStyle: 'medium',
    timeStyle: 'short',
    hour12: true,
    ...options,
  });

export const EGYPT_TIME_ZONE_NAME = EGYPT_TIME_ZONE;
