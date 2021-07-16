# Usage:
# cat stats.json | jq -R -f filter.jq

fromjson? |
{
 time: .time | (. - (3600*5) | strftime("%Y-%m-%d %H:%M:%S")),
 brokers:
   [ .brokers[] | select(.req.Produce > 0) | {
     (.nodeid | tostring): {
        "nodeid": .nodeid,
        "state": .state,
        "stateage": (.stateage/1000000.0),
        "connects": .connects,
        "rtt_p99":  .rtt.p99,
        "throttle": .throttle.cnt,
        "outbuf_cnt": .outbuf_cnt,
        "outbuf_msg_cnt": .outbuf_msg_cnt,
        "waitresp_cnt": .waitresp_cnt,
        "Produce": .req.Produce,
        "Metadata": .req.Metadata,
        "toppar_cnt": (.toppars | length)
      }
    }
    ],

 topics:
  [ .topics[] | select(.batchcnt.cnt > 0) | {
   (.topic): {
     "batchsize_p99": .batchsize.p99,
     "batchcnt_p99": .batchcnt.p99,
     "toppars": (.partitions[] | {
        (.partition | tostring): {
          leader: .leader,
          msgq_cnt: .msgq_cnt,
          xmit_msgq_cnt: .xmit_msgq_cnt,
          txmsgs: .txmsgs,
          msgs_inflight: .msgs_inflight
         }
       }),
   }
  } ]
}