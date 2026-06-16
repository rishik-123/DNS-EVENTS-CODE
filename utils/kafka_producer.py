import json
import logging
from typing import Dict, Any
from kafka import KafkaProducer
import config

logger = logging.getLogger("kafka_producer")

class DNSKafkaProducer:
    #CONNECTS TO THE BOOTSTRAP BROKER
    #SETS TIMEOUT OF 5000ms so if kafka is down screen will not freeze 
    def __init__(self):
        self.producer = None
        if not getattr(config, "KAFKA_ENABLED", False):
            logger.info("Kafka integration is disabled in config.")
            return

        try:
            logger.info(f"Initializing Kafka Producer connecting to {config.KAFKA_BOOTSTRAP_SERVERS}...")
            self.producer = KafkaProducer(
                bootstrap_servers=config.KAFKA_BOOTSTRAP_SERVERS,
                value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                key_serializer=lambda k: k.encode('utf-8') if k else None,
                request_timeout_ms=5000,
                max_block_ms=5000
            )
            logger.info("Kafka Producer initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize Kafka Producer: {e}", exc_info=True)
            self.producer = None

#Inspects the incoming SOC events. 
# If the event's alerts list contains security findings, 
# it routes the message to the dns-alerts topic. 
# Otherwise, it defaults to dns-events-raw. It Uses routing key
    def send_event(self, event_wrapper: Dict[str, Any]):
        if not self.producer:
            return
        
        try:
            # Extract internal data (fallback to "data" if using old schema)
            soc_event = event_wrapper.get("payload", event_wrapper.get("data", {}))
            
            # Route all events to the single raw events topic
            topic = getattr(config, "KAFKA_TOPIC_RAW", "dns-events-raw")
            
            # Extract key: the query domain for partition keying
            key = None
            dns_data = soc_event.get("dns", {})
            if dns_data:
                key = dns_data.get("query")
            
            # KafkaProducer.send is asynchronous
            self.producer.send(topic, key=key, value=event_wrapper)
            self.producer.flush()  # Flush immediately to ensure low-latency delivery
            logger.debug(f"Event for '{key}' sent to Kafka topic '{topic}'")
        except Exception as e:
            logger.error(f"Failed to send event to Kafka: {e}")

#cleanup
    def close(self):
        if self.producer:
            try:
                logger.info("Flushing and closing Kafka Producer...")
                self.producer.flush()
                self.producer.close()
                logger.info("Kafka Producer closed.")
            except Exception as e:
                logger.error(f"Error closing Kafka Producer: {e}")
