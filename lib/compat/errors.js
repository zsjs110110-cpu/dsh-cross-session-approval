export class HarnessError extends Error {
  constructor(message, code) { super(message); this.name = 'HarnessError'; this.code = code; }
}
