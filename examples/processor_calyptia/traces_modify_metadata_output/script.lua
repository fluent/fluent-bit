function process_traces(tag, ts, span, metadata)
  metadata.resourceSpan.resource.droppedAttributesCount = 10
  metadata.resourceSpan.schemaUrl = 'https://www.google2.com'
  metadata.scopeSpan.schemaUrl = 'https://www.google.com'
  metadata.scopeSpan.scope.name = 'scope-span'
  metadata.scopeSpan.scope.version = 'd.e.f'
  metadata.scopeSpan.scope.droppedAttributesCount = 5
  span.startTimeUnixNano = 10
  span.endTimeUnixNano = 20
  return MODIFY, ts, span, metadata
end
