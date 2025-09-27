/*
  Warnings:

  - Changed the type of `result` on the `AuditLog` table. No cast exists, the column would be dropped and recreated, which cannot be done if there is data, since the column is required.

*/
-- CreateEnum
CREATE TYPE "public"."AuditResult" AS ENUM ('SUCCESS', 'FAILURE');

-- AlterTable
ALTER TABLE "public"."AuditLog" DROP COLUMN "result",
ADD COLUMN     "result" "public"."AuditResult" NOT NULL;
