function process_metrics(tag, ts, metric)
  for _, sample in ipairs(metric.metrics) do
    sample.timestamp = 100
  end
  if metric.name == 'kubernetes_network_load_counter' then
    for _, sample in ipairs(metric.metrics) do
      if sample.labels then
        sample.labels.hostname = nil
      end
    end
  end
  metric.name = 'metric_' .. metric.name
  return MODIFY, ts, metric
end
