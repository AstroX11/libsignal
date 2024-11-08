class ProtocolAddress {
	static from(encodedAddress) {
		if (typeof encodedAddress !== 'string' || !encodedAddress.match(/.*\.\d+/)) {
			return null;
		}
		const parts = encodedAddress.split('.');
		return new this(parts[0], parseInt(parts[1]));
	}

	constructor(id, deviceId) {
		this.id = typeof id === 'string' && id.indexOf('.') === -1 ? id : null;
		this.deviceId = typeof deviceId === 'number' ? deviceId : null;
	}

	toString() {
		return `${this.id}.${this.deviceId}`;
	}

	is(other) {
		return other instanceof ProtocolAddress && other.id === this.id && other.deviceId === this.deviceId;
	}
}

module.exports = ProtocolAddress;
