export type ProposalState = "pending" | "executing" | "completed" | "failed" | "expired" | "cancelled";
export type PrincipalId = typeof OWNER_PRINCIPAL_ID;

export const OWNER_PRINCIPAL_ID = "owner-1";
export const COMMAND_MAX_LENGTH = 4096;
export const READ_SCOPE_MAX_LENGTH = 4096;
export const COMMAND_TIMEOUT_MAX_MS = 60_000;
export const COMMAND_OUTPUT_MAX_BYTES = 128 * 1024;
export const COMMAND_TIMEOUT_DEFAULT_MS = 60_000;
export const COMMAND_OUTPUT_DEFAULT_BYTES = 32 * 1024;
export const PROJECT_TASK_TIMEOUT_MAX_MS = 10 * 60_000;
export const PROJECT_TASK_TIMEOUT_DEFAULT_MS = 5 * 60_000;
export const PROJECT_TASK_OUTPUT_MAX_BYTES = 1024 * 1024;
export const PROJECT_TASK_OUTPUT_DEFAULT_BYTES = 256 * 1024;
export const DOCUMENT_MAX_BYTES = 2 * 1024 * 1024;
export const SCRIPT_RUN_TIMEOUT_MAX_MS = 15 * 60_000;
export const SCRIPT_RUN_OUTPUT_MAX_BYTES = 1024 * 1024;
