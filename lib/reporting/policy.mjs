export const DAILY_REPORT_CAP = 25
export const overDailyCap = (recentCount) => Number(recentCount) >= DAILY_REPORT_CAP
