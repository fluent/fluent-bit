function value(field, parts)
{
    split(field, parts, "=")
    return parts[2] + 0
}

function text_value(field, parts)
{
    split(field, parts, "=")
    return parts[2]
}

$1 == "mode=heap" {
    key = text_value($2) "/" value($5) "/" value($6)
    heap_time[key] = value($10)
    heap_rss[key] = value($11)
}

$1 == "mode=arena" && value($7) == 8192 && value($8) == 0 {
    key = text_value($2) "/" value($5) "/" value($6)
    cpu_ratio = value($10) / heap_time[key]
    rss_ratio = value($11) / heap_rss[key]
    case_count++
    cpu_ratio_sum += cpu_ratio
    rss_ratio_sum += rss_ratio
    if (cpu_ratio < 1.0) {
        cpu_wins++
    }
    if (rss_ratio <= 1.0) {
        rss_nonregressions++
    }
    printf("case=%s cpu_ratio=%.3f rss_ratio=%.3f\n",
           key, cpu_ratio, rss_ratio)
}

END {
    printf("summary_cases=%d cpu_wins=%d rss_nonregressions=%d " \
           "mean_cpu_ratio=%.3f mean_rss_ratio=%.3f\n",
           case_count, cpu_wins, rss_nonregressions,
           cpu_ratio_sum / case_count, rss_ratio_sum / case_count)
}
