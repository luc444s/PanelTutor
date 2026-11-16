import { cn } from "./cn";

type PaginationProps = {
  page: number;
  totalPages: number;
  onChange: (page: number) => void;
  className?: string;
  previousLabel?: string;
  nextLabel?: string;
};

function ChevronLeft() {
  return (
    <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M15 6l-6 6 6 6" />
    </svg>
  );
}

function ChevronRight() {
  return (
    <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M9 6l6 6-6 6" />
    </svg>
  );
}

function getPageNumbers(current: number, total: number): (number | "ellipsis")[] {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1);

  if (current <= 4) {
    return [1, 2, 3, 4, 5, "ellipsis", total];
  }
  if (current >= total - 3) {
    return [1, "ellipsis", total - 4, total - 3, total - 2, total - 1, total];
  }
  return [1, "ellipsis", current - 1, current, current + 1, "ellipsis", total];
}

export function Pagination({
  page,
  totalPages,
  onChange,
  className,
  previousLabel = "Previous page",
  nextLabel = "Next page",
}: PaginationProps) {
  if (totalPages <= 1) return null;

  const pages = getPageNumbers(page, totalPages);

  return (
    <nav aria-label="pagination" className={cn("flex max-w-full flex-wrap items-center justify-center gap-1", className)}>
      <button
        type="button"
        disabled={page <= 1}
        onClick={() => onChange(page - 1)}
        className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-border text-muted-foreground transition hover:bg-accent hover:text-foreground disabled:cursor-not-allowed disabled:opacity-40 sm:h-9 sm:w-9"
        aria-label={previousLabel}
      >
        <ChevronLeft />
      </button>

      <div className="flex items-center justify-center gap-1">
        {pages.map((p, i) =>
          p === "ellipsis" ? (
            <span key={`e-${i}`} className="inline-flex h-8 w-8 shrink-0 items-center justify-center text-sm text-muted-foreground sm:h-9 sm:w-9">
              ...
            </span>
          ) : (
            <button
              key={p}
              type="button"
              onClick={() => onChange(p)}
              className={cn(
                "inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-md text-xs font-medium transition sm:h-9 sm:w-9 sm:text-sm",
                p === page
                  ? "bg-primary text-primary-foreground"
                  : "text-muted-foreground hover:bg-accent hover:text-foreground"
              )}
            >
              {p}
            </button>
          )
        )}
      </div>

      <button
        type="button"
        disabled={page >= totalPages}
        onClick={() => onChange(page + 1)}
        className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-border text-muted-foreground transition hover:bg-accent hover:text-foreground disabled:cursor-not-allowed disabled:opacity-40 sm:h-9 sm:w-9"
        aria-label={nextLabel}
      >
        <ChevronRight />
      </button>
    </nav>
  );
}
