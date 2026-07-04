import "server-only";
import { Queue } from "bullmq";
import IORedis from "ioredis";

let queue: Queue | undefined;
export function getScanQueue() {
  if (!queue) {
    const connection = new IORedis(process.env.REDIS_URL ?? "redis://localhost:6379", { maxRetriesPerRequest: null });
    queue = new Queue("scan.passive", { connection: connection as never, defaultJobOptions: { attempts: 2, backoff: { type: "exponential", delay: 3000 }, removeOnComplete: 100, removeOnFail: 500 } });
  }
  return queue;
}
