import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import {
  actOnTenantResource,
  listTenantResources,
  tenantKeys,
  type TenantResponse,
  type TenantResource,
} from "../api";
import { Alert } from "@systutor/shell/ui/alert";
import { Button } from "@systutor/shell/ui/button";
import { Dialog } from "@systutor/shell/ui/dialog";
import { useT } from "@/i18n/use-i18n";

type Props = { tenant: TenantResponse | null; onClose: () => void };
type ResourceAction = "start" | "stop" | "restart" | "remove";

export function TenantResourcesDialog({ tenant, onClose }: Props) {
  const t = useT();
  const queryClient = useQueryClient();
  const resourcesQuery = useQuery({
    queryKey: tenantKeys.resources(tenant?.id ?? ""),
    queryFn: () => listTenantResources(tenant!.id),
    enabled: Boolean(tenant),
  });
  const actionMutation = useMutation({
    mutationFn: ({ resource, action }: { resource: TenantResource; action: ResourceAction }) =>
      actOnTenantResource(tenant!.id, resource, action),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: tenantKeys.resources(tenant!.id) });
      toast.success(t("Resource action dispatched"));
    },
  });

  return (
    <Dialog open={Boolean(tenant)} title={t("Resources — {name}").replace("{name}", tenant?.name ?? "")} onClose={onClose}>
      <div className="space-y-3">
        {resourcesQuery.isLoading && <p className="text-sm text-muted-foreground">{t("Loading resources...")}</p>}
        {resourcesQuery.error && <Alert title={t("Error")}>{(resourcesQuery.error as Error).message}</Alert>}
        {actionMutation.error && <Alert title={t("Error")}>{(actionMutation.error as Error).message}</Alert>}
        {resourcesQuery.data?.resources.map((resource) => (
          <div key={`${resource.kind}:${resource.resource_id}`} className="space-y-2 rounded border border-border p-3">
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="text-sm font-medium text-foreground">{resource.name}</p>
                <p className="font-mono text-xs text-muted-foreground">{resource.kind} · {resource.container_name}</p>
                <p className="text-xs text-muted-foreground">{resource.state} · {resource.runtime} · {resource.image}</p>
                {resource.endpoint && <a className="text-xs text-primary underline" href={resource.endpoint} target="_blank" rel="noreferrer">{resource.endpoint}</a>}
              </div>
            </div>
            <div className="flex flex-wrap gap-2">
              {(["start", "stop", "restart", "remove"] as ResourceAction[]).map((action) => (
                <Button key={action} size="sm" variant="secondary" disabled={actionMutation.isPending} onClick={() => actionMutation.mutate({ resource, action })}>
                  {t(action[0].toUpperCase() + action.slice(1))}
                </Button>
              ))}
            </div>
          </div>
        ))}
        {resourcesQuery.data?.resources.length === 0 && <p className="text-sm text-muted-foreground">{t("No resources")}</p>}
        <div className="flex justify-end"><Button size="sm" variant="secondary" onClick={onClose}>{t("Close")}</Button></div>
      </div>
    </Dialog>
  );
}
