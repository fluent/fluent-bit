#include <iostream>
#include <librdkafka/rdkafkacpp.h>


int main() {
  std::cout << "librdkafka++ " << RdKafka::version_str() << std::endl;

  RdKafka::Conf *conf = RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL);

  std::string features;

  if (conf->get("builtin.features", features) != RdKafka::Conf::CONF_OK) {
    std::cerr << "conf_get failed" << std::endl;
    return 1;
  }

  std::cout << "builtin.features " << features << std::endl;

  std::string errstr;
  RdKafka::Producer *producer = RdKafka::Producer::create(conf, errstr);
  if (!producer) {
    std::cerr << "Producer::create failed: " << errstr << std::endl;
    return 1;
  }

  delete conf;

  std::cout << "client name " << producer->name() << std::endl;


  delete producer;

  return 0;
}
