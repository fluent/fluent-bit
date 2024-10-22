function process_metrics(tag, ts, metric)
  for _, sample in ipairs(metric.metrics) do
    sample.timestamp = 0
  end

  if metric.name == 'kubernetes_network_load_counter' then
    for _, sample in ipairs(metric.metrics) do
      if sample.labels then
        sample.labels.hostname = nil
      end
    end
  end
  if metric.name == 'kubernetes_network_load_gauge' then
    table.insert(metric.metrics, {
      timestamp = 0,
      value = 42,
      labels = {
        hello = 'world'
      }
    })
  end
  return MODIFY, ts, metric
end
