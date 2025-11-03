import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.const import CONF_ID

CONF_RECORDS = "records"
CONF_DOMAIN = "domain"
CONF_IP = "ip"

DEPENDENCIES = ["wifi", "network"]

dns_proxy_ns = cg.esphome_ns.namespace("dns_proxy")
DnsRedirect = dns_proxy_ns.class_("DnsRedirect", cg.Component)

CONFIG_SCHEMA = cv.Schema({
    cv.GenerateID(): cv.declare_id(DnsRedirect),
    cv.Required(CONF_RECORDS): cv.ensure_list(cv.Schema({
        cv.Required(CONF_DOMAIN): cv.string,
        cv.Required(CONF_IP): cv.string,
    })),
}).extend(cv.COMPONENT_SCHEMA)


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)

    for record in config[CONF_RECORDS]:
        cg.add(var.add_record(record[CONF_DOMAIN], record[CONF_IP]))
