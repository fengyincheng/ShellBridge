import { isSandboxRequestError, type SandboxedShell } from "./sandboxed-shell.js";
import { publicSandboxError, SandboxFailure, type PublicSandboxError } from "./sandbox-errors.js";

export type SandboxRunner = Pick<SandboxedShell, "run"> & Partial<Pick<SandboxedShell, "initialize">>;

type CapabilityHealth =
  | { status: "ready" }
  | ({ status: "degraded" } & PublicSandboxError);

export class SandboxCapability implements Pick<SandboxedShell, "run"> {
  private failure: PublicSandboxError | undefined;
  private recovery: Promise<void> | undefined;

  constructor(
    private readonly runner: SandboxRunner,
    private readonly observe: (health: CapabilityHealth) => void = () => undefined,
  ) {}

  async start(): Promise<void> {
    if (!this.runner.initialize) {
      this.markReady();
      return;
    }
    try {
      await this.runner.initialize();
      this.markReady();
    } catch (error) {
      this.markDegraded(publicSandboxError(error, { phase: "root_view_prepare", fallbackPhase: "root_view_prepare" }));
    }
  }

  health(): CapabilityHealth {
    return this.failure ? { status: "degraded", ...this.failure } : { status: "ready" };
  }

  async run(request: Parameters<SandboxedShell["run"]>[0]): ReturnType<SandboxedShell["run"]> {
    if (this.failure) {
      if (!this.failure.retryable) throw new SandboxFailure(this.failure);
      await this.recover();
    }
    try {
      return await this.runner.run(request);
    } catch (error) {
      if (isSandboxRequestError(error)) throw error;
      const failure = publicSandboxError(error, { phase: "command_execution", timeoutMs: request.timeoutMs });
      if (failure.phase !== "command_execution") this.markDegraded(failure);
      throw error;
    }
  }

  private async recover(): Promise<void> {
    if (!this.runner.initialize) {
      this.markReady();
      return;
    }
    if (this.recovery) return this.recovery;
    const attempt = (async () => {
      try {
        await this.runner.initialize!();
        this.markReady();
      } catch (error) {
        this.markDegraded(publicSandboxError(error, { phase: "root_view_prepare", fallbackPhase: "root_view_prepare" }));
        throw error;
      }
    })();
    this.recovery = attempt;
    try {
      await attempt;
    } finally {
      if (this.recovery === attempt) this.recovery = undefined;
    }
  }

  private markReady(): void {
    const changed = this.failure !== undefined;
    this.failure = undefined;
    if (changed) this.observe({ status: "ready" });
  }

  private markDegraded(failure: PublicSandboxError): void {
    this.failure = failure;
    this.observe({ status: "degraded", ...failure });
  }
}
