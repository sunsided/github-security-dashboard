// Live updates from the server (see crates/server/src/realtime.rs): fetch a
// short-lived token, open the WebSocket, send the token first. Events are
// hints to reload data from the REST API.

import { reconnectDelay, refreshDelay } from './backoff';

export type LiveStatus = 'connecting' | 'live' | 'offline';

export type LiveEvent =
	| { type: 'run.started' }
	| { type: 'run.finished'; run: number | null; status: string; repos: number; errors: number }
	| { type: 'alerts.changed'; repositories: string[]; events: number }
	| { type: 'digest.delivered'; target: string; outcome: string }
	/** Missed events or a new connection: reload everything. */
	| { type: 'resync' };

/** Close codes from the server. */
const TOKEN_EXPIRED = 4002;

async function fetchToken(): Promise<string> {
	const response = await fetch('/api/realtime/token', {
		method: 'POST',
		// Required by the server's CSRF guard (see crates/server/src/guard.rs).
		headers: { 'x-dashboard-request': '1' }
	});
	if (!response.ok) throw new Error(`token: ${response.status}`);
	const body = (await response.json()) as { token: string };
	return body.token;
}

class LiveConnection {
	status = $state<LiveStatus>('offline');

	#socket: WebSocket | null = null;
	#attempt = 0;
	#everConnected = false;
	#stopped = true;
	#refreshTimer: ReturnType<typeof setTimeout> | undefined;
	#retryTimer: ReturnType<typeof setTimeout> | undefined;
	#listeners = new Set<(event: LiveEvent) => void>();

	/** Subscribes to events; returns the unsubscribe function. */
	subscribe(listener: (event: LiveEvent) => void): () => void {
		this.#listeners.add(listener);
		return () => this.#listeners.delete(listener);
	}

	/** Resolves with the first event of `type`, or `null` after `timeoutMs`. */
	waitFor(type: LiveEvent['type'], timeoutMs: number): Promise<LiveEvent | null> {
		return new Promise((resolve) => {
			const timer = setTimeout(() => {
				unsubscribe();
				resolve(null);
			}, timeoutMs);
			const unsubscribe = this.subscribe((event) => {
				if (event.type === type) {
					clearTimeout(timer);
					unsubscribe();
					resolve(event);
				}
			});
		});
	}

	start() {
		if (!this.#stopped) return;
		this.#stopped = false;
		void this.#connect();
	}

	stop() {
		this.#stopped = true;
		clearTimeout(this.#refreshTimer);
		clearTimeout(this.#retryTimer);
		this.#socket?.close(1000);
		this.#socket = null;
		this.status = 'offline';
	}

	#emit(event: LiveEvent) {
		for (const listener of this.#listeners) listener(event);
	}

	async #connect() {
		if (this.#stopped) return;
		this.status = 'connecting';
		let token: string;
		try {
			token = await fetchToken();
		} catch {
			this.#retry();
			return;
		}
		const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
		const socket = new WebSocket(`${scheme}://${location.host}/api/realtime`);
		this.#socket = socket;

		socket.onopen = () => socket.send(JSON.stringify({ connect: { token } }));
		socket.onmessage = (message) => this.#receive(JSON.parse(message.data as string));
		socket.onclose = (close) => {
			if (this.#socket !== socket) return;
			this.#socket = null;
			clearTimeout(this.#refreshTimer);
			this.status = 'offline';
			// An expired token just needs a new one, no need to wait.
			if (close.code === TOKEN_EXPIRED) this.#attempt = 0;
			this.#retry(close.code === TOKEN_EXPIRED ? 0 : undefined);
		};
	}

	#receive(message: {
		connected?: { expires_at: string };
		refreshed?: { expires_at: string };
		event?: LiveEvent;
		resync?: object;
	}) {
		const expiry = message.connected ?? message.refreshed;
		if (expiry) {
			this.#scheduleRefresh(Date.parse(expiry.expires_at));
		}
		if (message.connected) {
			this.status = 'live';
			this.#attempt = 0;
			// Whatever happened while disconnected is unknown: reload.
			if (this.#everConnected) this.#emit({ type: 'resync' });
			this.#everConnected = true;
		}
		if (message.event) this.#emit(message.event);
		if (message.resync) this.#emit({ type: 'resync' });
	}

	#scheduleRefresh(expiresAt: number) {
		clearTimeout(this.#refreshTimer);
		this.#refreshTimer = setTimeout(
			async () => {
				const socket = this.#socket;
				if (!socket || socket.readyState !== WebSocket.OPEN) return;
				try {
					socket.send(JSON.stringify({ refresh: { token: await fetchToken() } }));
				} catch {
					// The server closes the connection at expiry; reconnecting
					// then fetches a new token.
				}
			},
			refreshDelay(expiresAt, Date.now())
		);
	}

	#retry(delay = reconnectDelay(this.#attempt)) {
		if (this.#stopped) return;
		this.#attempt += 1;
		clearTimeout(this.#retryTimer);
		this.#retryTimer = setTimeout(() => void this.#connect(), delay);
	}
}

export const live = new LiveConnection();
