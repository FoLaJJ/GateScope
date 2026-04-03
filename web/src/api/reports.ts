import { downloadFile } from './client'

export function exportExcel(taskId: string) {
  return downloadFile(`/reports/${taskId}/excel`, `GateScope_Report_${taskId}.xlsx`)
}
