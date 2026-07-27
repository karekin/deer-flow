"use client";

import { ClipboardCheckIcon } from "lucide-react";
import Link from "next/link";
import { useEffect, useMemo, useState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  WorkspaceBody,
  WorkspaceContainer,
  WorkspaceHeader,
} from "@/components/workspace/workspace-container";
import { useI18n } from "@/core/i18n/hooks";
import { useInfiniteThreads } from "@/core/threads/hooks";
import {
  isInternalTestThread,
  pathOfThread,
  titleOfThread,
} from "@/core/threads/utils";
import { formatTimeAgo } from "@/core/utils/datetime";

export default function AcceptanceRecordsPage() {
  const { t } = useI18n();
  const [search, setSearch] = useState("");
  const {
    data: infiniteThreads,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
  } = useInfiniteThreads();

  const records = useMemo(() => {
    const query = search.trim().toLowerCase();
    return (infiniteThreads?.pages.flat() ?? [])
      .filter(isInternalTestThread)
      .filter(
        (thread) =>
          query.length === 0 ||
          titleOfThread(thread).toLowerCase().includes(query),
      );
  }, [infiniteThreads, search]);

  useEffect(() => {
    document.title = `${t.pages.acceptanceRecords} - ${t.pages.appName}`;
  }, [t.pages.acceptanceRecords, t.pages.appName]);

  return (
    <WorkspaceContainer>
      <WorkspaceHeader />
      <WorkspaceBody>
        <div className="flex size-full flex-col">
          <header className="mx-auto flex w-full max-w-(--container-width-md) shrink-0 flex-col gap-4 px-4 pt-8">
            <div className="flex items-start gap-3">
              <div className="bg-muted rounded-lg p-2">
                <ClipboardCheckIcon className="size-5" />
              </div>
              <div>
                <h1 className="text-xl font-semibold">
                  {t.acceptanceRecords.title}
                </h1>
                <p className="text-muted-foreground mt-1 text-sm">
                  {t.acceptanceRecords.description}
                </p>
              </div>
            </div>
            <Input
              type="search"
              className="h-11"
              placeholder={t.acceptanceRecords.search}
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
          </header>
          <main className="min-h-0 flex-1">
            <ScrollArea className="size-full py-4">
              <div className="mx-auto flex w-full max-w-(--container-width-md) flex-col px-4">
                {records.length === 0 ? (
                  <div className="text-muted-foreground py-12 text-center text-sm">
                    {t.acceptanceRecords.empty}
                  </div>
                ) : (
                  records.map((thread) => (
                    <Link
                      key={thread.thread_id}
                      href={pathOfThread(thread)}
                      className="hover:bg-muted/50 rounded-md border-b p-4 transition-colors"
                    >
                      <div className="font-medium">{titleOfThread(thread)}</div>
                      {thread.updated_at && (
                        <div className="text-muted-foreground mt-2 text-sm">
                          {formatTimeAgo(thread.updated_at)}
                        </div>
                      )}
                    </Link>
                  ))
                )}
                {hasNextPage && (
                  <div className="flex justify-center p-4">
                    <Button
                      variant="outline"
                      onClick={() => void fetchNextPage()}
                      disabled={isFetchingNextPage}
                    >
                      {isFetchingNextPage
                        ? t.chats.loadingMore
                        : t.chats.loadOlderChats}
                    </Button>
                  </div>
                )}
              </div>
            </ScrollArea>
          </main>
        </div>
      </WorkspaceBody>
    </WorkspaceContainer>
  );
}
