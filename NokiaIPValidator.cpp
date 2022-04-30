#include "NokiaIPValidator.h"

#include <sstream>
#include <exception>
#include <regex>

using namespace std;

const ui32 NokiaIPValidator::m_dataQueueMaxSize = 65'000;
const regex NokiaIPValidator::m_ipv4Validator("(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])");
const regex NokiaIPValidator::m_ipv6Validator("((([0-9a-fA-F]){1,4})\\:){7}([0-9a-fA-F]){1,4}");

NokiaIPValidator::NokiaIPValidator()
    : m_pIPDataQueue(new Queue())
    , m_pUniqueIPV4Addresses(new UnorderedSet())
    , m_pUniqueIPV6Addresses(new UnorderedSet())
{
    promise<bool> p;
    m_bConsumerThreadRunningStatus = p.get_future();
    m_consumerThread = move(thread(&NokiaIPValidator::startValidation, this, move(p)));
}

NokiaIPValidator::~NokiaIPValidator()
{
    auto status = m_bConsumerThreadRunningStatus.wait_for(0ms);
    while (status != future_status::ready)
    {
        continue;
        this_thread::sleep_for(1ms);
    }
    if (m_consumerThread.joinable())
        m_consumerThread.join();
}

/*static*/ bool NokiaIPValidator::isValidIPV4Address(const std::string& ip) noexcept
{
    if (ip.empty())
        return false;

    return regex_match(ip, m_ipv4Validator);
}

/*static*/ bool NokiaIPValidator::isValidIPV6Address(const std::string& ip) noexcept
{
    if (ip.empty())
        return false;

    return regex_match(ip, m_ipv6Validator);
}

/*static*/ ui32 NokiaIPValidator::getHashKey(const std::string& ip, const bool bIsIPV6)
{
    if (ip.empty())
        return 0;

    auto localIp(ip);
    ui32 hashKey = bIsIPV6 ? 0x0 : 0;
    size_t endPos = 0;
    auto separator = bIsIPV6 ? ':' : '.';
    ui32 segmentIdx = bIsIPV6 ? 0x1 : 1;

    try
    {
        while (endPos != string::npos && (bIsIPV6 ? (segmentIdx <= 0x7) : (segmentIdx <=3)))
        {
            auto segment = localIp.substr(0, localIp.find_first_of(separator) - 1);
            localIp = localIp.substr(endPos + 1);
            endPos = localIp.find_first_of(separator);
            istringstream is(segment);
            ui32 val = 0;
            
            if (bIsIPV6)
                is >> hex >> val;
            else
                is >> val;

            if ((bIsIPV6 ? (val < 0x0) : (val < 0)))
                throw exception();

            hashKey += (val / segmentIdx) + (val % segmentIdx);
            ++segmentIdx;
        }
    }
    catch (...)
    {
        throw current_exception;
    }
    return hashKey;
}

bool NokiaIPValidator::isUniqueIPV4Address(const ui32& hashKey, const bool bIPV4) noexcept
{
    if (!bIPV4 || hashKey == 0)
        return false;

    scoped_lock<shared_mutex> readLock(m_readMtxIP);
    if (m_pUniqueIPV4Addresses->find(hashKey) == m_pUniqueIPV4Addresses->end())
        return true;
    
    return false;
}

bool NokiaIPValidator::isUniqueIPV6Address(const ui32& hashKey, const bool bIPV6) noexcept
{
    if (!bIPV6 || hashKey == 0)
        return false;

    scoped_lock<shared_mutex> readLock(m_readMtxIP);
    if (m_pUniqueIPV6Addresses->find(hashKey) == m_pUniqueIPV6Addresses->end())
        return true;

    return false;
}

void NokiaIPValidator::pushData(const std::string& ip)
{
    if (ip.empty())
        return;
    {
        scoped_lock<shared_mutex> readLock(m_readMtxIP);
        while (m_pIPDataQueue->size() == m_dataQueueMaxSize)
            continue;
    }
    scoped_lock<mutex> writeLock(m_dataQueueMtx);
    m_pIPDataQueue->emplace(ip);
}

void NokiaIPValidator::processData()
{
    if (!m_pIPDataQueue->empty())
    {
        auto ipAddr = m_pIPDataQueue->front();
        {
            scoped_lock<mutex> writeLock(m_dataQueueMtx);
            m_pIPDataQueue->pop();
        }
        auto bIsValidIPV4 = isValidIPV4Address(ipAddr);
        auto bIsValidIPV6 = isValidIPV6Address(ipAddr);

        if (bIsValidIPV4)
        {
            auto hashKey = getHashKey(ipAddr, false);
            auto bIsUnique = isUniqueIPV4Address(hashKey, true);
            {
                scoped_lock<mutex> writeLock(m_writeMtxIPV4);
                if (bIsUnique)
                    m_pUniqueIPV4Addresses->emplace(hashKey);
                else
                    m_pUniqueIPV4Addresses->erase(hashKey);
            }
            ++m_totalIPV4AddrCnt;
        }
        else if (bIsValidIPV6)
        {
            auto hashKey = getHashKey(ipAddr, true);
            auto bIsUnique = isUniqueIPV6Address(hashKey, true);
            {
                scoped_lock<mutex> writeLock(m_writeMtxIPV6);
                if (bIsUnique)
                    m_pUniqueIPV6Addresses->emplace(hashKey);
                else
                    m_pUniqueIPV6Addresses->erase(hashKey);
            }
            ++m_totalIPV6AddrCnt;
        }
        else
        {
            ++m_invalidIPAddrCnt;
        }
    }
}

void NokiaIPValidator::startValidation(std::promise<bool> bFinished)
{    
    while (!m_bIsReadingDataDone)
    {
        while (!m_pIPDataQueue->empty())
            processData();
    }
    while (!m_pIPDataQueue->empty())
        processData();

    m_bIsProcessingDataDone = true;
}
