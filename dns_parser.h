#pragma once
#include <array>
#include<iostream>
#include <string>

#include <vector>
#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#include <arpa/inet.h>
#endif

#include <stdexcept>
#include <variant>
using std::variant;
using std::string;
using std::vector;

using std::array;


// DNS 域名编码工具

namespace dns_utils {
	static void encode_dns_name(std::vector<uint8_t>& buffer, const std::string& name) {
		size_t start = 0;
        while (true) {
            size_t dot = name.find('.', start);
            if (dot == std::string::npos) dot = name.length();

            uint8_t label_len = static_cast<uint8_t>(dot - start);
            buffer.push_back(label_len);
            buffer.insert(buffer.end(), name.begin() + start, name.begin() + dot);

            start = dot + 1;
            if (start > name.length()) break;
        }
        buffer.push_back(0); // 结束符
	}

    // 解码DNS标签格式域名（处理简单情况，暂不支持压缩指针）
    static std::string decode_dns_name(const uint8_t* buffer, size_t& pos) {
        std::string name;
        while (true) {
            uint8_t len = buffer[pos++];
            if (len == 0) break;

            name.append(reinterpret_cast<const char*>(buffer + pos), len);
            name.push_back('.');
            pos += len;
        }
        if (!name.empty() && name.back() == '.') name.pop_back();
        return name;
    }
}













class DnsHeader {

public:
    //协议标志位掩码
    static constexpr uint16_t QR_MASK = 0x8000; // 查询/响应标志， 0为查询，1为响应
    static constexpr uint16_t OPCODE_MASK = 0x7800; // 操作码， 0为标准查询， 1为反向查询， 2为服务器状态
    static constexpr uint16_t AA_MASK = 0x0400; // 授权回答
    static constexpr uint16_t TC_MASK = 0x0200; // 截断标志
    static constexpr uint16_t RD_MASK = 0x0100; // 期望递归
    static constexpr uint16_t RA_MASK = 0x0080; // 可用递归
    static constexpr uint16_t Z_MASK = 0x0040; // 保留字段
    static constexpr uint16_t RCODE_MASK = 0x000F; // 响应码， 0为无错误， 1为格式错误， 2为服务器失败， 3为域名不存在， 4为未实现， 5为拒绝响应

    // 操作码枚举
    enum class Opcode : uint8_t {
        QUERY = 0,   // 标准查询
        IQUERY = 1,   // 反向查询
        STATUS = 2    // 服务器状态
    };

    // 响应码枚举
    enum class Rcode : uint8_t {
        NO__ERROR = 0,  // 无错误
        FORM_ERR = 1,  // 格式错误
        SERV_FAIL = 2,  // 服务器失败
        NXDOMAIN = 3,  // 域名不存在
        NOT_IMP = 4,  // 未实现
        REFUSED = 5   // 拒绝响应
    };

    // 构造函数
    DnsHeader() : id(0), flags(0), question_count(0),
        answer_count(0), authority_count(0), additional_count(0) {
    }




    // 字段访问方法
    void set_id(uint16_t new_id) { id = new_id; }
    uint16_t get_id() const { return id; }

    // 标志位操作
    bool is_response() const { return (flags & QR_MASK) != 0; }
    void set_qr(bool response) {
        flags = response ? (flags | QR_MASK) : (flags & ~QR_MASK);
    }

    Opcode get_opcode() const {
        return static_cast<Opcode>((flags & OPCODE_MASK) >> 11);
    }
    void set_opcode(Opcode opcode) {
        flags = (flags & ~OPCODE_MASK) |
            (static_cast<uint16_t>(opcode) << 11);
    }

    bool is_authoritative() const { return (flags & AA_MASK) != 0; }
    void set_aa(bool aa) {
        flags = aa ? (flags | AA_MASK) : (flags & ~AA_MASK);
    }

    bool is_truncated() const { return (flags & TC_MASK) != 0; }
    void set_tc(bool tc) {
        flags = tc ? (flags | TC_MASK) : (flags & ~TC_MASK);
    }

    bool recursion_desired() const { return (flags & RD_MASK) != 0; }
    void set_rd(bool rd) {
        flags = rd ? (flags | RD_MASK) : (flags & ~RD_MASK);
    }

    bool recursion_available() const { return (flags & RA_MASK) != 0; }
    void set_ra(bool ra) {
        flags = ra ? (flags | RA_MASK) : (flags & ~RA_MASK);
    }

    Rcode get_rcode() const {
        return static_cast<Rcode>(flags & RCODE_MASK);
    }
    void set_rcode(Rcode rcode) {
        flags = (flags & ~RCODE_MASK) | static_cast<uint16_t>(rcode);
    }

    // 记录数操作
    void set_question_count(uint16_t count) { question_count = count; }
    uint16_t get_question_count() const { return question_count; }

    void set_answer_count(uint16_t count) { answer_count = count; }
    uint16_t get_answer_count() const { return answer_count; }

    void set_authority_count(uint16_t count) { authority_count = count; }
    uint16_t get_authority_count() const { return authority_count; }

    void set_additional_count(uint16_t count) { additional_count = count; }
    uint16_t get_additional_count() const { return additional_count; }

    // 协议分析输出
    void print() const {
        std::cout << "[DNS Header]\n"
            << "  Transaction ID: 0x" << std::hex << id << std::dec << "\n"
            << "  Flags: 0x" << std::hex << flags << std::dec << "\n"
            << "    QR: " << (is_response() ? "Response" : "Query") << "\n"
            << "    Opcode: " << opcode_to_string(get_opcode()) << "\n"
            << "    AA: " << (is_authoritative() ? "Authoritative" : "") << "\n"
            << "    TC: " << (is_truncated() ? "Truncated" : "") << "\n"
            << "    RD: " << (recursion_desired() ? "Recursion desired" : "") << "\n"
            << "    RA: " << (recursion_available() ? "Recursion available" : "") << "\n"
            << "    RCODE: " << rcode_to_string(get_rcode()) << "\n"
            << "  Questions: " << question_count << "\n"
            << "  Answers: " << answer_count << "\n"
            << "  Authority RRs: " << authority_count << "\n"
            << "  Additional RRs: " << additional_count << "\n\n";
    }

    // 新增 serialize 方法
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buffer;
        uint16_t net_id = htons(id);
        uint16_t net_flags = htons(flags);
        uint16_t net_question_count = htons(question_count);
        uint16_t net_answer_count = htons(answer_count);
        uint16_t net_authority_count = htons(authority_count);
        uint16_t net_additional_count = htons(additional_count);

        buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(&net_id),
            reinterpret_cast<const uint8_t*>(&net_id) + 2);
        buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(&net_flags),
            reinterpret_cast<const uint8_t*>(&net_flags) + 2);
        buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(&net_question_count),
            reinterpret_cast<const uint8_t*>(&net_question_count) + 2);
        buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(&net_answer_count),
            reinterpret_cast<const uint8_t*>(&net_answer_count) + 2);
        buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(&net_authority_count),
            reinterpret_cast<const uint8_t*>(&net_authority_count) + 2);
        buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(&net_additional_count),
            reinterpret_cast<const uint8_t*>(&net_additional_count) + 2);

        return buffer;
    }

    void deserialize(const uint8_t* buffer, size_t& pos) {
        id = ntohs(*reinterpret_cast<const uint16_t*>(buffer + pos));
        pos += 2;
        flags = ntohs(*reinterpret_cast<const uint16_t*>(buffer + pos));
        pos += 2;
        question_count = ntohs(*reinterpret_cast<const uint16_t*>(buffer + pos));
        pos += 2;
        answer_count = ntohs(*reinterpret_cast<const uint16_t*>(buffer + pos));
        pos += 2;
        authority_count = ntohs(*reinterpret_cast<const uint16_t*>(buffer + pos));
        pos += 2;
        additional_count = ntohs(*reinterpret_cast<const uint16_t*>(buffer + pos));
        pos += 2;
    }

private:
	uint16_t id;
	uint16_t flags;
	uint16_t question_count; 
	uint16_t answer_count;   
	uint16_t authority_count;
	uint16_t additional_count;


    static const char* opcode_to_string(Opcode op) {
        switch (op) {
        case Opcode::QUERY:  return "QUERY";
        case Opcode::IQUERY: return "IQUERY";
        case Opcode::STATUS:  return "STATUS";
        default:              return "UNKNOWN";
        }
    }

    static const char* rcode_to_string(Rcode code) {
        switch (code) {
        case Rcode::NO__ERROR:  return "NO_ERROR";
        case Rcode::FORM_ERR:  return "FORMAT_ERROR";
        case Rcode::SERV_FAIL: return "SERVER_FAILURE";
        case Rcode::NXDOMAIN:  return "NXDOMAIN";
        case Rcode::NOT_IMP:   return "NOT_IMPLEMENTED";
        case Rcode::REFUSED:   return "REFUSED";
        default:               return "UNKNOWN_CODE";
        }
    }

    


};

// 枚举查询类型
enum class QType : uint16_t {
    A = 1,      // IPv4地址
    NS = 2,      // 名称服务器
    CNAME = 5,      // 规范名称
    SOA = 6,      // 权威记录
    MX = 15,     // 邮件交换
    TXT = 16,     // 文本记录
    AAAA = 28,     // IPv6地址
    AXFR = 252,    // 区域传输（特殊查询类型）
    ANY = 255     // 所有记录（特殊查询类型）
};
class DnsQuery {
private:

	string name;
    QType type;
	uint16_t qclass;
public:
	DnsQuery() : type(QType::A), qclass(1) {}

    // serialize
	std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> data;
        dns_utils::encode_dns_name(data, name);


        // 网络字节序转换
        uint16_t net_type = htons(static_cast<uint16_t>(type));
        uint16_t net_class = htons(qclass);

        // 写入二进制数据
        data.insert(data.end(), reinterpret_cast<uint8_t*>(&net_type),
            reinterpret_cast<uint8_t*>(&net_type) + 2);
        data.insert(data.end(), reinterpret_cast<uint8_t*>(&net_class),
            reinterpret_cast<uint8_t*>(&net_class) + 2);
        return data;
	}

	//deserialize
    void deserialize(const uint8_t* buffer, size_t& pos) {
        name = dns_utils::decode_dns_name(buffer, pos);
        type = static_cast<QType>(ntohs(*reinterpret_cast<const uint16_t*>(buffer + pos)));
        pos += 2;
        qclass = ntohs(*reinterpret_cast<const uint16_t*>(buffer + pos));
        pos += 2;
    }

    // 新增访问方法
    void set_name(const string& name) { this->name = name; }
	void set_type(QType type) { this->type = type; }
    string get_name() const { return name; }
    QType get_type() const { return type; }
    uint16_t get_qclass() const { return qclass; }
};



// 枚举资源记录类型
enum class RRType {
	A = 1,       // IPv4地址
	AAAA = 28,   // IPv6地址
	NS = 2,      // 名称服务器
	CNAME = 5,	 // 规范名称记录
};


// 资源记录的数据类型（根据 RRType 解析）
struct RRData {
	variant <
		vector<uint8_t>,  // 原始数据（用于未知类型）
		string,            // 字符串（如 NS、CNAME 记录）
		
		
		array<uint8_t, 4>,    // A 记录（IPv4 地址）
		array<uint8_t, 16>    // AAAA 记录（IPv6 地址）
	> data;
    // 根据 RRType 解析数据
    
    void parse(RRType type, const uint8_t* rdata, uint16_t rdlength) {
        switch (type) {
        case RRType::A:
            if (rdlength != 4) throw std::runtime_error("Invalid A record");
            data = *reinterpret_cast<const array<uint8_t, 4>*>(rdata);
            break;
        case RRType::AAAA:
            if (rdlength != 16) throw std::runtime_error("Invalid AAAA record");
            data = *reinterpret_cast<const array<uint8_t, 16>*>(rdata);
            break;
        case RRType::NS:
        case RRType::CNAME: {
            size_t pos = 0;
            data = dns_utils::decode_dns_name(rdata, pos);
            break;
        }
       
        default:
            data = vector<uint8_t>(rdata, rdata + rdlength);
        }
    }
};

// answer, authority, additional 结构相同，只定义一个类
class DnsResourceRecord {
private:
	string name;
	RRType type;
	uint16_t rclass;
	uint32_t ttl;
	uint16_t data_length;
	RRData data;

public:

    // 实现 get_serialized_rdata 方法
    std::vector<uint8_t> get_serialized_rdata() const {
        std::vector<uint8_t> rdata;
        if (std::holds_alternative<std::vector<uint8_t>>(data.data)) {
            const auto& rawData = std::get<std::vector<uint8_t>>(data.data);
            rdata.insert(rdata.end(), rawData.begin(), rawData.end());
        }
        else if (std::holds_alternative<std::string>(data.data)) {
            const auto& strData = std::get<std::string>(data.data);
            dns_utils::encode_dns_name(rdata, strData);
        }
        else if (std::holds_alternative<std::array<uint8_t, 4>>(data.data)) {
            const auto& ipv4Data = std::get<std::array<uint8_t, 4>>(data.data);
            rdata.insert(rdata.end(), ipv4Data.begin(), ipv4Data.end());
        }
        else if (std::holds_alternative<std::array<uint8_t, 16>>(data.data)) {
            const auto& ipv6Data = std::get<std::array<uint8_t, 16>>(data.data);
            rdata.insert(rdata.end(), ipv6Data.begin(), ipv6Data.end());
        }
        return rdata;
    }
    // 新增序列化方法
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buffer;
        dns_utils::encode_dns_name(buffer, name);

        // 写入头部字段
        uint16_t net_type = htons(static_cast<uint16_t>(type));
        uint16_t net_class = htons(rclass);
        uint32_t net_ttl = htonl(ttl);

        buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(&net_type),
            reinterpret_cast<const uint8_t*>(&net_type) + 2);
        buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(&net_class),
            reinterpret_cast<const uint8_t*>(&net_class) + 2);
        buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(&net_ttl),
            reinterpret_cast<const uint8_t*>(&net_ttl) + 4);

        // 处理RDATA
        std::vector<uint8_t> rdata = get_serialized_rdata();
        uint16_t net_rdlength = htons(rdata.size());
        buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(&net_rdlength),
            reinterpret_cast<const uint8_t*>(&net_rdlength) + 2);
        buffer.insert(buffer.end(), rdata.begin(), rdata.end());
        return buffer;
    }

    // 新增反序列化方法
    void deserialize(const uint8_t* buffer, size_t& pos) {
        name = dns_utils::decode_dns_name(buffer, pos);
        type = static_cast<RRType>(ntohs(*reinterpret_cast<const uint16_t*>(buffer + pos)));
        pos += 2;
        rclass = ntohs(*reinterpret_cast<const uint16_t*>(buffer + pos));
        pos += 2;
        ttl = ntohl(*reinterpret_cast<const uint32_t*>(buffer + pos));
        pos += 4;
        data_length = ntohs(*reinterpret_cast<const uint16_t*>(buffer + pos));
        pos += 2;
        data.parse(type, buffer + pos, data_length);
        pos += data_length;
    }

    // 新增打印方法
    void print() const {
        std::cout << "  Name: " << name << "\n"
            << "  Type: " << static_cast<int>(type) << "\n"
            << "  Class: " << rclass << "\n"
            << "  TTL: " << ttl << "\n";
        // 添加具体数据打印逻辑
    }
    RRType get_type() const {
        return type;
    }

    const RRData& get_data() const {
        return data;
    }
    
};


class DnsPacket {
public:
	DnsHeader header;
	vector<DnsQuery> queries;
	vector<DnsResourceRecord> answers;
	vector<DnsResourceRecord> authority;
	vector<DnsResourceRecord> additional;

    void serialize_records(const vector<DnsResourceRecord>& records,
        std::vector<uint8_t>& packet) const {
        for (const auto& rr : records) {
            auto rr_data = rr.serialize();
            packet.insert(packet.end(), rr_data.begin(), rr_data.end());
        }
    }

    void parse_records(const uint8_t* data, size_t& pos,
        uint16_t count, vector<DnsResourceRecord>& records) {
        records.clear();
        for (int i = 0; i < count; ++i) {
            DnsResourceRecord rr;
            rr.deserialize(data, pos);
            records.push_back(rr);
        }
    }

public:
    // 新增完整数据包序列化
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> packet;

        // 序列化头部
        auto header_data = header.serialize();
        packet.insert(packet.end(), header_data.begin(), header_data.end());

        // 序列化查询部分
        for (const auto& query : queries) {
            auto query_data = query.serialize();
            packet.insert(packet.end(), query_data.begin(), query_data.end());
        }

        // 序列化各资源记录部分
        serialize_records(answers, packet);
        serialize_records(authority, packet);
        serialize_records(additional, packet);

        return packet;
    }

    // 新增完整数据包解析
    void deserialize(const uint8_t* data, size_t length) {
        size_t pos = 0;

        // 解析头部
        header.deserialize(data, pos);

        // 解析查询部分
        queries.clear();
        for (int i = 0; i < header.get_question_count(); ++i) {
            DnsQuery query;
            query.deserialize(data, pos);
            queries.push_back(query);
        }

        // 解析各资源记录部分
        parse_records(data, pos, header.get_answer_count(), answers);
        parse_records(data, pos, header.get_authority_count(), authority);
        parse_records(data, pos, header.get_additional_count(), additional);
    }

};
