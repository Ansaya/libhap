#ifndef HAP_SERVER_DNS_SD_TXTRECORD
#define HAP_SERVER_DNS_SD_TXTRECORD

#include <string>

namespace hap {
namespace server {
namespace dns_sd {

    typedef struct sd_ctx_t SD_CTX;

    class TXTRecord
    {
    public:
        /**
         * @brief Construct a new service discovery record object
         * 
         * @param name Service name
         * @param type Service type
         */
        TXTRecord(
            const std::string& name, 
            const std::string& type);
        
        ~TXTRecord();

        /**
         * @brief Update TXT record with current object state
         * 
         * @param interface_index Interface to advertise the service on (0 = any)
         * @param port Service port
         * @return int Zero on success, non-zero on error
         */
        int updateEntry(uint32_t interface_index, uint16_t port);

        /**
         * @brief Remove TXT record from DNS
         * 
         */
        void removeEntry();

        /**
         * @brief Set TXT record value for given key
         * 
         * @param key Key name
         * @param value Value for given key
         * @return int Zero on success, non-zero on error
         */
        int setValue(const std::string& key, const std::string& value);

        /**
         * @brief Remove TXT record value for given key
         * 
         * @param key Key name
         * @return int Zero on success, non-zero on error
         */
        int removeValue(const std::string& key);

    private:
        const std::string _name;
        const std::string _type;
        SD_CTX* _context;

    };

}
}
}

#endif