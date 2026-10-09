set(src
  in_amqp.c)

FLB_PLUGIN(in_amqp "${src}" rabbitmq::rabbitmq)
