#ifndef IP_VALIDATOR
#define IP_VALIDATOR

#include <unordered_set>        //  std::unordered_set to keep unique addresses
#include <shared_mutex>         //  std::shared_mutex for read mutexes
#include <string>               //  std::string
#include <regex>                //  std::regex for regular expressions
#include <queue>                //  std::queue for data queue
#include <atomic>               // std::atomic
#include <chrono>               // std::chrono
#include <cstdint>              // std::int_fast64_t, std::uint_fast32_t
#include <algorithm>            // std::algorithm
#include <future>               // std::future, std::promise
#include <memory>               // std::shared_ptr, std::unique_ptr
#include <mutex>                // std::mutex, std::scoped_lock
#include <thread>               // std::this_thread, std::thread

using ui32 = std::uint_fast32_t;
using ui64 = std::uint_fast64_t;

using Queue = std::queue<std::string>;
using UnorderedSet = std::unordered_set<ui32>;
using AtomicBool = std::atomic<bool>;

// ============================================================================================= //
 //                                    Begin class IP validator                                    //

/**
  * @brief A C++17 IP validator class. It vaildates the read IP addresses from a text file to check whether it is an IPV4 or IPV6 or invalid one
  * - It runs a consumer thread to read from a queue of string for validation until either the reading is over and all the read data in the queue
  * - is processed. It also gives the counts of valid IPV4/IPV6/invalid addresses it processed including the unique ones for each IPV4 & IPV6
  * - along with their's total counts
  */
class IPValidator
{
public:
    /**
     * @brief Construct a new IP validator with default values.
     * 
     */
    IPValidator();

    /**
     * @brief Destruct the IP validator when all the data are processed
     *
     */
    ~IPValidator();

    /**
     * @brief All other constructors of this class are forbidden for now
     */
    IPValidator(const IPValidator& rhs) = delete;
    IPValidator(IPValidator&& rhs) = delete;
    IPValidator& operator=(const IPValidator& rhs) = delete;
    IPValidator& operator=(IPValidator&& rhs) = delete;

    /**
     * @brief Returns the unique IPV4 address count it has encountered so far
     */
    size_t getUniqueIPV4AddrCnt() const noexcept { return m_pUniqueIPV4Addresses->size(); }

    /**
     * @brief Returns the unique IPV6 address count it has encountered so far
     */
    size_t getUniqueIPV6AddrCnt() const noexcept { return m_pUniqueIPV6Addresses->size(); }

    /**
     * @brief Returns the total IPV6 address count it has encountered so far
     */
    size_t getTotalIPV6AddrCnt() const noexcept { return m_totalIPV6AddrCnt; }

    /**
     * @brief Returns the total IPV4 address count it has encountered so far
     */
    size_t getTotalIPV4AddrCnt() const noexcept { return m_totalIPV4AddrCnt; }

    /**
     * @brief Returns the total invalid address count it has encountered so far
     */
    size_t getInvalidIPAddrCnt() const noexcept { return m_invalidIPAddrCnt; }

    /**
     * @brief Returns the status of file processing
     */
    bool isProcessingDone() const noexcept { return m_bIsProcessingDataDone; }

    /**
     * @brief Validates whether the IP address is a vaild IPV4 one or not
     *
     * @param ip The IP address to be validated
     * 
     * @return True on success false on failure
     */
    static bool isValidIPV4Address(const std::string& ip) noexcept;

    /**
     * @brief Validates whether the IP address is a vaild IPV6 one or not
     *
     * @param ip The IP address to be validated
     *
     * @return True on success false on failure
     */
    static bool isValidIPV6Address(const std::string& ip) noexcept;

    /**
     * @brief Pushes the read IP address from the file into the data queue. If the data queue size is full (65,000) then it waits. It also increments the total IP read count each time
     * - a push request is made into the data queue
     *
     * @param ip The IP address to be validated
     * 
     */
    void pushData(const std::string& ip);

    /**
     * @brief Checks whether the IP address which is of IPV4 type is a new one in the line or it is just old wine in new bottle.
     * - If the second param is false then it returns false straight away
     *
     * @param hashKey The equivalent hask key for the IPV4 address
     * @param bIPV4 The type of the address. For a validation it has to be true
     * 
     * @return True on success
     *
     */
    bool isUniqueIPV4Address(const ui32& hashKey, const bool bIPV4) noexcept;

    /**
     * @brief Checks whether the IP address which is of IPV6 type is a new one in the line or it is just old wine in new bottle.
     * - If the second param is false then it returns false straight away
     *
     * @param hashKey The equivalent hask key in hex for the IPV6 address
     * @param bIPV6 The type of the address. For a validation it has to be true
     *
     * @return True on success
     *
     */
    bool isUniqueIPV6Address(const ui32& hashKey, const bool bIPV6) noexcept;

    /**
     * @brief Sets the indicator to notify whether the reading of the file is completed or not
     *
     * @param val The value which is going to set the indicator
     *
     */
    void setReadingDataDone(const bool val) noexcept { m_bIsReadingDataDone = val; }

private:
    /**
     * @brief Construct a hash key from the passed IP in uint_fast32_t format
     * 
     * @param ip The IP address for which the hash key would be generated
     * @param bIsIPV6 Whether the IP is of IPV6 or IPV4 type. If false, then IPV4 assumed
     * 
     * @return A constructed hash key in uint_fast32_t type
     */
    static ui32 getHashKey(const std::string& ip, const bool bIsIPV6);

    /**
     * @brief Starts the validation of the read IP addresses in a continous running thread using thread pool. Basically it is the consumer thread which will process the data.
     * - It reads from the data queue for any incoming IP address, pops it up for processing and again checks. Continue this till it comes to know that the data queue is empty
     * - and the reading of data is also over. It also updates the unique IPV4/IPV6/invalid address counts in the process.
     * 
     * @Param bFinished True on clean exit otherwise false
     */
    void startValidation(std::promise<bool> bFinished);

    /**
     * @brief Processes the IP address data to determine it's validity and updating various counts accordingly
     */
    void processData();

    /**
     * @brief An atomic bool to indicate whether the reading of IP addresses from the text file is completed or not. Initially set to false. Only to be set to true when the file reading is over
     */
    AtomicBool m_bIsReadingDataDone = false;

    /**
     * @brief An atomic bool to indicate whether the processing of IP addresses from the text file is completed or not. Initially set to false. Only to be set to true when the file processing is over
     */
    AtomicBool m_bIsProcessingDataDone = false;

    /**
     * @brief A queue of std strings to hold the incoming IP data. At any given point of time it's max size could be 65K.
     */
    std::unique_ptr<Queue> m_pIPDataQueue;

    /**
     * @brief An uonrdered set to hold unique IPV4 addresses in the form of hash keys of type uint_fast32_t
     */
    std::unique_ptr<UnorderedSet> m_pUniqueIPV4Addresses;

    /**
     * @brief An uonrdered set to hold unique IPV6 addresses in the form of hash keys of type uint_fast32_t
     */
    std::unique_ptr<UnorderedSet> m_pUniqueIPV6Addresses;

    /**
     * @brief An atomic uint_fast64_t type to hold the count of total valid IPV4 addresses read
     */
    std::atomic<ui64> m_totalIPV4AddrCnt    = 0;

    /**
     * @brief An atomic uint_fast64_t type to hold the count of total valid IPV6 addresses read
     */
    std::atomic<ui64> m_totalIPV6AddrCnt    = 0;

    /**
     * @brief An atomic uint_fast64_t type to hold the count of total invalid IP addresses read
     */
    std::atomic<ui64> m_invalidIPAddrCnt    = 0;

    /**
     * @brief A write mutex for container modification operations related to IPV4 addresses
     */
    std::mutex m_writeMtxIPV4 = {};

    /**
     * @brief A write mutex for container modification operations related to IPV6 addresses
     */
    std::mutex m_writeMtxIPV6 = {};

    /**
     * @brief A read mutex for container read operations related to IPV4 addresses
     */
    std::shared_mutex m_readMtxIP = {};

    /**
     * @brief A write mutex for container modification operations related to IP addresses
     */
    std::mutex m_dataQueueMtx = {};

    /**
     * @brief A future to hold the consumer thread running status
     */
    std::future<bool> m_bConsumerThreadRunningStatus = {};

    /**
     * @brief A condition variable for the synchronization purpose between various writer threads
     */
    std::condition_variable m_condVar = {};

    /**
     * @brief A thread object holding the details of the invoked consumer thread
     */
    std::thread m_consumerThread = {};

    /**
     * @brief A constant value of 65,000 which would be the maximum data queue size on any given point of time (needed to avoid overloading of task queue in thread pool object)
     */
    static const ui32 m_dataQueueMaxSize;

    /**
     * @brief A constant regular expression value to vaildate IPV4 address
     */
    static const std::regex m_ipv4Validator;

    /**
     * @brief A constant regular expression value to vaildate IPV6 address
     */
    static const std::regex m_ipv6Validator;
};

//                                     End class IP Validator                                     //
// ============================================================================================= //

#endif // !IP_VALIDATOR


