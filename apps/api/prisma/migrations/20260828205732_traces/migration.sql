-- CreateTable
CREATE TABLE "TraceBundle" (
    "id" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "windowFrom" TIMESTAMP(3) NOT NULL,
    "windowTo" TIMESTAMP(3) NOT NULL,
    "ingestedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "spanCount" INTEGER NOT NULL,
    "rootServices" TEXT[],

    CONSTRAINT "TraceBundle_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "TraceEdge" (
    "id" TEXT NOT NULL,
    "bundleId" TEXT NOT NULL,
    "fromService" TEXT NOT NULL,
    "toService" TEXT NOT NULL,
    "observations" INTEGER NOT NULL,
    "operation" TEXT NOT NULL,

    CONSTRAINT "TraceEdge_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "TraceBundle_ingestedAt_idx" ON "TraceBundle"("ingestedAt");

-- CreateIndex
CREATE INDEX "TraceEdge_bundleId_idx" ON "TraceEdge"("bundleId");

-- CreateIndex
CREATE UNIQUE INDEX "TraceEdge_bundleId_fromService_toService_key" ON "TraceEdge"("bundleId", "fromService", "toService");

-- AddForeignKey
ALTER TABLE "TraceEdge" ADD CONSTRAINT "TraceEdge_bundleId_fkey" FOREIGN KEY ("bundleId") REFERENCES "TraceBundle"("id") ON DELETE CASCADE ON UPDATE CASCADE;
