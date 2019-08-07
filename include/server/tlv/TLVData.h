#ifndef HAP_SERVER_TLV_TLVDATA
#define HAP_SERVER_TLV_TLVDATA

#include <map>
#include <vector>

namespace hap {
namespace server {
namespace tlv {

    class TLVData
    {
    public:
        /**
         * @brief Initialize an empty TLV data object
         * 
         */
        TLVData();

        /**
         * @brief Initialize a TLV data object from given TLV buffer
         * 
         * @param buffer TLV items buffer
         * @param buffer_length Buffer length
         */
        TLVData(const uint8_t* buffer, size_t buffer_length);

        /**
         * @brief Initialize a TLV data object from given TLV buffer
         * 
         * @param buffer TLV items buffer
         */
        TLVData(const std::vector<uint8_t>& buffer);

        virtual ~TLVData();

        /**
         * @brief Get item with given type
         * 
         * @param item_type Item type
         * @return const std::vector<uint8_t>* Value associated to given type
         */
        const std::vector<uint8_t>* getItem(const uint8_t item_type) const;

        /**
         * @brief Set TLV item with given type and value 
         * 
         * @param item_type TLV type
         * @param item_value TLV value
         */
        void setItem(const uint8_t item_type, const std::vector<uint8_t>& item_value);

        /**
         * @brief Set TLV item with given type and value 
         * 
         * @param item_type TLV type
         * @param value TLV value buffer
         * @param value_length Value buffer length
         */
        void setItem(const uint8_t item_type, const uint8_t* value, size_t value_length);

        /**
         * @brief Remove item with given type
         * 
         * @param item_type TLV type to remove
         */
        void removeItem(const uint8_t item_type);

        /**
         * @brief Serialize all TLV items into a single buffer
         * 
         * @return std::vector<uint8_t> TLV items buffer
         */
        std::vector<uint8_t> serialize() const;

    private:
        std::map<uint8_t, std::vector<uint8_t>> _items;
        
    };
    
}
}
}

#endif