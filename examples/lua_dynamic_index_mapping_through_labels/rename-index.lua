function indexcb_replace(tag, timestamp, record)
  local updated_log = {}local k8s_metadata
  local extracted_value = ""
  log = record
  if type(log) == 'table'
  then
    k8s_metadata = log["kubernetes"]
    if type(k8s_metadata) == 'table'
    then
      extrLabels = k8s_metadata["labels"]
      if (extrLabels ~= nil)
      then
        extracted_label = k8s_metadata["labels"]["splunk-index"]
        if (extracted_label ~= nil)
        then
          new_index = extracted_label
          updated_log = log
          updated_log["index"] = new_index
        else
          extracted_value = k8s_metadata["namespace_name"]
          extracted_value = "default_" .. extracted_value
          updated_log = log
          updated_log["index"] = extracted_value
        end
      else
        extracted_value = k8s_metadata["namespace_name"]
        extracted_value = "default_" .. extracted_value
        updated_log = log
        updated_log["index"] = extracted_value
      end
    else
      return -1, timestamp, updated_log
    end
  else
    return -1, timestamp, updated_log
  end
return 2, timestamp, updated_log
end
