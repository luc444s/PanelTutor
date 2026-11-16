import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef } from "react";

import { appsKeys, getOperation } from "./api";
import { isTerminalOperation } from "./logic";

export function useOperationPolling(
  operationId: string | null,
  applicationId?: string,
  onFinalized?: (operationId: string) => void,
) {
  const queryClient = useQueryClient();
  const finalized = useRef<string | null>(null);
  const query = useQuery({
    queryKey: appsKeys.operation(operationId ?? "idle"),
    queryFn: () => getOperation(operationId!),
    enabled: Boolean(operationId),
    refetchInterval: (state) => isTerminalOperation(state.state.data) ? false : 2_000,
    retry: false,
  });

  useEffect(() => {
    if (!operationId || !isTerminalOperation(query.data) || finalized.current === operationId) return;
    finalized.current = operationId;
    void queryClient.invalidateQueries({ queryKey: appsKeys.applications });
    if (applicationId) {
      void queryClient.invalidateQueries({ queryKey: appsKeys.application(applicationId) });
      void queryClient.invalidateQueries({ queryKey: appsKeys.deployments(applicationId) });
      void queryClient.invalidateQueries({ queryKey: appsKeys.operations(applicationId) });
      void queryClient.invalidateQueries({ queryKey: appsKeys.releases(applicationId) });
    }
    onFinalized?.(operationId);
  }, [applicationId, onFinalized, operationId, query.data, queryClient]);

  return query;
}
