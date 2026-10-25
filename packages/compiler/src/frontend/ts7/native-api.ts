import { Ts7Api } from "./api.js";
import { checkerServerName } from "./checker-server.js";
import { attachNativeTs7Process, spawnNativeTs7Wire } from "./native-process.js";
import { Ts7RpcClient } from "./rpc-client.js";
import type { Ts7FileSystem } from "./rpc-filesystem.js";
import { Ts7Wire } from "./rpc-wire.js";

/** The native driver supplies its installed TypeScript executable path.
 * Package discovery is separate from starting and owning a server. */
export function createNativeTs7Api(options: {
  executable: string;
  cwd: string;
  fs: Ts7FileSystem;
  collectTiming?: boolean;
  shared?: boolean;
}): Ts7Api {
  const timing = options.collectTiming ?? false;
  const server =
    options.shared === false ? null : checkerServerName(options.executable, options.cwd, timing);
  const shared =
    server === null
      ? null
      : attachNativeTs7Process(server, options.executable, options.cwd, timing);
  if (shared !== null) {
    const rpc = new Ts7RpcClient(new Ts7Wire(shared));
    try {
      // A server that ended the connection leaves this build to start its own.
      rpc.requestText("ping", "null");
      return new Ts7Api(rpc, options.fs, timing);
    } catch {
      rpc.close();
    }
  }
  return new Ts7Api(
    new Ts7RpcClient(spawnNativeTs7Wire(options.executable, options.cwd, timing)),
    options.fs,
    timing,
  );
}
