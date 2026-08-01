import { CalendarClock } from "lucide-react";
import Link from "next/link";

import { Button } from "@/components/ui/button";
import { useI18n } from "@/core/i18n/hooks";

export function ThreadScheduledTasksLink({
  threadId,
  assistantId,
}: {
  threadId: string;
  assistantId?: string;
}) {
  const { t } = useI18n();
  return (
    <Button variant="outline" size="sm" asChild>
      <Link
        aria-label={t.sidebar.scheduledTasks}
        href={`/workspace/scheduled-tasks?thread_id=${encodeURIComponent(threadId)}${assistantId ? `&assistant_id=${encodeURIComponent(assistantId)}` : ""}`}
      >
        <CalendarClock />
        <span className="hidden sm:inline">{t.sidebar.scheduledTasks}</span>
      </Link>
    </Button>
  );
}
