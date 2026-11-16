import { useOperationPolling } from "../useOperationPolling";

/** Headless operation tracker: keeps polling until the operation is terminal
 * and lets `useOperationPolling` invalidate the affected queries. */
export function OperationWatcher({ operationId, applicationId, onFinalized }: {
  operationId: string;
  applicationId?: string;
  onFinalized: (operationId: string) => void;
}) {
  useOperationPolling(operationId, applicationId, onFinalized);
  return null;
}
