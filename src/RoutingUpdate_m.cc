//
// Generated file, do not edit! Created by opp_msgtool 6.1 from RoutingUpdate.msg.
//

// Disable warnings about unused variables, empty switch stmts, etc:
#ifdef _MSC_VER
#  pragma warning(disable:4101)
#  pragma warning(disable:4065)
#endif

#if defined(__clang__)
#  pragma clang diagnostic ignored "-Wshadow"
#  pragma clang diagnostic ignored "-Wconversion"
#  pragma clang diagnostic ignored "-Wunused-parameter"
#  pragma clang diagnostic ignored "-Wc++98-compat"
#  pragma clang diagnostic ignored "-Wunreachable-code-break"
#  pragma clang diagnostic ignored "-Wold-style-cast"
#elif defined(__GNUC__)
#  pragma GCC diagnostic ignored "-Wshadow"
#  pragma GCC diagnostic ignored "-Wconversion"
#  pragma GCC diagnostic ignored "-Wunused-parameter"
#  pragma GCC diagnostic ignored "-Wold-style-cast"
#  pragma GCC diagnostic ignored "-Wsuggest-attribute=noreturn"
#  pragma GCC diagnostic ignored "-Wfloat-conversion"
#endif

#include <iostream>
#include <sstream>
#include <memory>
#include <type_traits>
#include "RoutingUpdate_m.h"

namespace omnetpp {

// Template pack/unpack rules. They are declared *after* a1l type-specific pack functions for multiple reasons.
// They are in the omnetpp namespace, to allow them to be found by argument-dependent lookup via the cCommBuffer argument

// Packing/unpacking an std::vector
template<typename T, typename A>
void doParsimPacking(omnetpp::cCommBuffer *buffer, const std::vector<T,A>& v)
{
    int n = v.size();
    doParsimPacking(buffer, n);
    for (int i = 0; i < n; i++)
        doParsimPacking(buffer, v[i]);
}

template<typename T, typename A>
void doParsimUnpacking(omnetpp::cCommBuffer *buffer, std::vector<T,A>& v)
{
    int n;
    doParsimUnpacking(buffer, n);
    v.resize(n);
    for (int i = 0; i < n; i++)
        doParsimUnpacking(buffer, v[i]);
}

// Packing/unpacking an std::list
template<typename T, typename A>
void doParsimPacking(omnetpp::cCommBuffer *buffer, const std::list<T,A>& l)
{
    doParsimPacking(buffer, (int)l.size());
    for (typename std::list<T,A>::const_iterator it = l.begin(); it != l.end(); ++it)
        doParsimPacking(buffer, (T&)*it);
}

template<typename T, typename A>
void doParsimUnpacking(omnetpp::cCommBuffer *buffer, std::list<T,A>& l)
{
    int n;
    doParsimUnpacking(buffer, n);
    for (int i = 0; i < n; i++) {
        l.push_back(T());
        doParsimUnpacking(buffer, l.back());
    }
}

// Packing/unpacking an std::set
template<typename T, typename Tr, typename A>
void doParsimPacking(omnetpp::cCommBuffer *buffer, const std::set<T,Tr,A>& s)
{
    doParsimPacking(buffer, (int)s.size());
    for (typename std::set<T,Tr,A>::const_iterator it = s.begin(); it != s.end(); ++it)
        doParsimPacking(buffer, *it);
}

template<typename T, typename Tr, typename A>
void doParsimUnpacking(omnetpp::cCommBuffer *buffer, std::set<T,Tr,A>& s)
{
    int n;
    doParsimUnpacking(buffer, n);
    for (int i = 0; i < n; i++) {
        T x;
        doParsimUnpacking(buffer, x);
        s.insert(x);
    }
}

// Packing/unpacking an std::map
template<typename K, typename V, typename Tr, typename A>
void doParsimPacking(omnetpp::cCommBuffer *buffer, const std::map<K,V,Tr,A>& m)
{
    doParsimPacking(buffer, (int)m.size());
    for (typename std::map<K,V,Tr,A>::const_iterator it = m.begin(); it != m.end(); ++it) {
        doParsimPacking(buffer, it->first);
        doParsimPacking(buffer, it->second);
    }
}

template<typename K, typename V, typename Tr, typename A>
void doParsimUnpacking(omnetpp::cCommBuffer *buffer, std::map<K,V,Tr,A>& m)
{
    int n;
    doParsimUnpacking(buffer, n);
    for (int i = 0; i < n; i++) {
        K k; V v;
        doParsimUnpacking(buffer, k);
        doParsimUnpacking(buffer, v);
        m[k] = v;
    }
}

// Default pack/unpack function for arrays
template<typename T>
void doParsimArrayPacking(omnetpp::cCommBuffer *b, const T *t, int n)
{
    for (int i = 0; i < n; i++)
        doParsimPacking(b, t[i]);
}

template<typename T>
void doParsimArrayUnpacking(omnetpp::cCommBuffer *b, T *t, int n)
{
    for (int i = 0; i < n; i++)
        doParsimUnpacking(b, t[i]);
}

// Default rule to prevent compiler from choosing base class' doParsimPacking() function
template<typename T>
void doParsimPacking(omnetpp::cCommBuffer *, const T& t)
{
    throw omnetpp::cRuntimeError("Parsim error: No doParsimPacking() function for type %s", omnetpp::opp_typename(typeid(t)));
}

template<typename T>
void doParsimUnpacking(omnetpp::cCommBuffer *, T& t)
{
    throw omnetpp::cRuntimeError("Parsim error: No doParsimUnpacking() function for type %s", omnetpp::opp_typename(typeid(t)));
}

}  // namespace omnetpp

Register_Class(RoutingUpdate)

RoutingUpdate::RoutingUpdate(const char *name, short kind) : ::omnetpp::cMessage(name, kind)
{
}

RoutingUpdate::RoutingUpdate(const RoutingUpdate& other) : ::omnetpp::cMessage(other)
{
    copy(other);
}

RoutingUpdate::~RoutingUpdate()
{
}

RoutingUpdate& RoutingUpdate::operator=(const RoutingUpdate& other)
{
    if (this == &other) return *this;
    ::omnetpp::cMessage::operator=(other);
    copy(other);
    return *this;
}

void RoutingUpdate::copy(const RoutingUpdate& other)
{
    this->senderId = other.senderId;
    this->destination = other.destination;
    this->nextHop = other.nextHop;
    this->cost = other.cost;
    this->sequenceNumber = other.sequenceNumber;
    this->hmac = other.hmac;
}

void RoutingUpdate::parsimPack(omnetpp::cCommBuffer *b) const
{
    ::omnetpp::cMessage::parsimPack(b);
    doParsimPacking(b,this->senderId);
    doParsimPacking(b,this->destination);
    doParsimPacking(b,this->nextHop);
    doParsimPacking(b,this->cost);
    doParsimPacking(b,this->sequenceNumber);
    doParsimPacking(b,this->hmac);
}

void RoutingUpdate::parsimUnpack(omnetpp::cCommBuffer *b)
{
    ::omnetpp::cMessage::parsimUnpack(b);
    doParsimUnpacking(b,this->senderId);
    doParsimUnpacking(b,this->destination);
    doParsimUnpacking(b,this->nextHop);
    doParsimUnpacking(b,this->cost);
    doParsimUnpacking(b,this->sequenceNumber);
    doParsimUnpacking(b,this->hmac);
}

const char * RoutingUpdate::getSenderId() const
{
    return this->senderId.c_str();
}

void RoutingUpdate::setSenderId(const char * senderId)
{
    this->senderId = senderId;
}

const char * RoutingUpdate::getDestination() const
{
    return this->destination.c_str();
}

void RoutingUpdate::setDestination(const char * destination)
{
    this->destination = destination;
}

const char * RoutingUpdate::getNextHop() const
{
    return this->nextHop.c_str();
}

void RoutingUpdate::setNextHop(const char * nextHop)
{
    this->nextHop = nextHop;
}

int RoutingUpdate::getCost() const
{
    return this->cost;
}

void RoutingUpdate::setCost(int cost)
{
    this->cost = cost;
}

long RoutingUpdate::getSequenceNumber() const
{
    return this->sequenceNumber;
}

void RoutingUpdate::setSequenceNumber(long sequenceNumber)
{
    this->sequenceNumber = sequenceNumber;
}

const char * RoutingUpdate::getHmac() const
{
    return this->hmac.c_str();
}

void RoutingUpdate::setHmac(const char * hmac)
{
    this->hmac = hmac;
}

class RoutingUpdateDescriptor : public omnetpp::cClassDescriptor
{
  private:
    mutable const char **propertyNames;
    enum FieldConstants {
        FIELD_senderId,
        FIELD_destination,
        FIELD_nextHop,
        FIELD_cost,
        FIELD_sequenceNumber,
        FIELD_hmac,
    };
  public:
    RoutingUpdateDescriptor();
    virtual ~RoutingUpdateDescriptor();

    virtual bool doesSupport(omnetpp::cObject *obj) const override;
    virtual const char **getPropertyNames() const override;
    virtual const char *getProperty(const char *propertyName) const override;
    virtual int getFieldCount() const override;
    virtual const char *getFieldName(int field) const override;
    virtual int findField(const char *fieldName) const override;
    virtual unsigned int getFieldTypeFlags(int field) const override;
    virtual const char *getFieldTypeString(int field) const override;
    virtual const char **getFieldPropertyNames(int field) const override;
    virtual const char *getFieldProperty(int field, const char *propertyName) const override;
    virtual int getFieldArraySize(omnetpp::any_ptr object, int field) const override;
    virtual void setFieldArraySize(omnetpp::any_ptr object, int field, int size) const override;

    virtual const char *getFieldDynamicTypeString(omnetpp::any_ptr object, int field, int i) const override;
    virtual std::string getFieldValueAsString(omnetpp::any_ptr object, int field, int i) const override;
    virtual void setFieldValueAsString(omnetpp::any_ptr object, int field, int i, const char *value) const override;
    virtual omnetpp::cValue getFieldValue(omnetpp::any_ptr object, int field, int i) const override;
    virtual void setFieldValue(omnetpp::any_ptr object, int field, int i, const omnetpp::cValue& value) const override;

    virtual const char *getFieldStructName(int field) const override;
    virtual omnetpp::any_ptr getFieldStructValuePointer(omnetpp::any_ptr object, int field, int i) const override;
    virtual void setFieldStructValuePointer(omnetpp::any_ptr object, int field, int i, omnetpp::any_ptr ptr) const override;
};

Register_ClassDescriptor(RoutingUpdateDescriptor)

RoutingUpdateDescriptor::RoutingUpdateDescriptor() : omnetpp::cClassDescriptor(omnetpp::opp_typename(typeid(RoutingUpdate)), "omnetpp::cMessage")
{
    propertyNames = nullptr;
}

RoutingUpdateDescriptor::~RoutingUpdateDescriptor()
{
    delete[] propertyNames;
}

bool RoutingUpdateDescriptor::doesSupport(omnetpp::cObject *obj) const
{
    return dynamic_cast<RoutingUpdate *>(obj)!=nullptr;
}

const char **RoutingUpdateDescriptor::getPropertyNames() const
{
    if (!propertyNames) {
        static const char *names[] = {  nullptr };
        omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
        const char **baseNames = base ? base->getPropertyNames() : nullptr;
        propertyNames = mergeLists(baseNames, names);
    }
    return propertyNames;
}

const char *RoutingUpdateDescriptor::getProperty(const char *propertyName) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    return base ? base->getProperty(propertyName) : nullptr;
}

int RoutingUpdateDescriptor::getFieldCount() const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    return base ? 6+base->getFieldCount() : 6;
}

unsigned int RoutingUpdateDescriptor::getFieldTypeFlags(int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldTypeFlags(field);
        field -= base->getFieldCount();
    }
    static unsigned int fieldTypeFlags[] = {
        FD_ISEDITABLE,    // FIELD_senderId
        FD_ISEDITABLE,    // FIELD_destination
        FD_ISEDITABLE,    // FIELD_nextHop
        FD_ISEDITABLE,    // FIELD_cost
        FD_ISEDITABLE,    // FIELD_sequenceNumber
        FD_ISEDITABLE,    // FIELD_hmac
    };
    return (field >= 0 && field < 6) ? fieldTypeFlags[field] : 0;
}

const char *RoutingUpdateDescriptor::getFieldName(int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldName(field);
        field -= base->getFieldCount();
    }
    static const char *fieldNames[] = {
        "senderId",
        "destination",
        "nextHop",
        "cost",
        "sequenceNumber",
        "hmac",
    };
    return (field >= 0 && field < 6) ? fieldNames[field] : nullptr;
}

int RoutingUpdateDescriptor::findField(const char *fieldName) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    int baseIndex = base ? base->getFieldCount() : 0;
    if (strcmp(fieldName, "senderId") == 0) return baseIndex + 0;
    if (strcmp(fieldName, "destination") == 0) return baseIndex + 1;
    if (strcmp(fieldName, "nextHop") == 0) return baseIndex + 2;
    if (strcmp(fieldName, "cost") == 0) return baseIndex + 3;
    if (strcmp(fieldName, "sequenceNumber") == 0) return baseIndex + 4;
    if (strcmp(fieldName, "hmac") == 0) return baseIndex + 5;
    return base ? base->findField(fieldName) : -1;
}

const char *RoutingUpdateDescriptor::getFieldTypeString(int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldTypeString(field);
        field -= base->getFieldCount();
    }
    static const char *fieldTypeStrings[] = {
        "string",    // FIELD_senderId
        "string",    // FIELD_destination
        "string",    // FIELD_nextHop
        "int",    // FIELD_cost
        "long",    // FIELD_sequenceNumber
        "string",    // FIELD_hmac
    };
    return (field >= 0 && field < 6) ? fieldTypeStrings[field] : nullptr;
}

const char **RoutingUpdateDescriptor::getFieldPropertyNames(int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldPropertyNames(field);
        field -= base->getFieldCount();
    }
    switch (field) {
        default: return nullptr;
    }
}

const char *RoutingUpdateDescriptor::getFieldProperty(int field, const char *propertyName) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldProperty(field, propertyName);
        field -= base->getFieldCount();
    }
    switch (field) {
        default: return nullptr;
    }
}

int RoutingUpdateDescriptor::getFieldArraySize(omnetpp::any_ptr object, int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldArraySize(object, field);
        field -= base->getFieldCount();
    }
    RoutingUpdate *pp = omnetpp::fromAnyPtr<RoutingUpdate>(object); (void)pp;
    switch (field) {
        default: return 0;
    }
}

void RoutingUpdateDescriptor::setFieldArraySize(omnetpp::any_ptr object, int field, int size) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount()){
            base->setFieldArraySize(object, field, size);
            return;
        }
        field -= base->getFieldCount();
    }
    RoutingUpdate *pp = omnetpp::fromAnyPtr<RoutingUpdate>(object); (void)pp;
    switch (field) {
        default: throw omnetpp::cRuntimeError("Cannot set array size of field %d of class 'RoutingUpdate'", field);
    }
}

const char *RoutingUpdateDescriptor::getFieldDynamicTypeString(omnetpp::any_ptr object, int field, int i) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldDynamicTypeString(object,field,i);
        field -= base->getFieldCount();
    }
    RoutingUpdate *pp = omnetpp::fromAnyPtr<RoutingUpdate>(object); (void)pp;
    switch (field) {
        default: return nullptr;
    }
}

std::string RoutingUpdateDescriptor::getFieldValueAsString(omnetpp::any_ptr object, int field, int i) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldValueAsString(object,field,i);
        field -= base->getFieldCount();
    }
    RoutingUpdate *pp = omnetpp::fromAnyPtr<RoutingUpdate>(object); (void)pp;
    switch (field) {
        case FIELD_senderId: return oppstring2string(pp->getSenderId());
        case FIELD_destination: return oppstring2string(pp->getDestination());
        case FIELD_nextHop: return oppstring2string(pp->getNextHop());
        case FIELD_cost: return long2string(pp->getCost());
        case FIELD_sequenceNumber: return long2string(pp->getSequenceNumber());
        case FIELD_hmac: return oppstring2string(pp->getHmac());
        default: return "";
    }
}

void RoutingUpdateDescriptor::setFieldValueAsString(omnetpp::any_ptr object, int field, int i, const char *value) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount()){
            base->setFieldValueAsString(object, field, i, value);
            return;
        }
        field -= base->getFieldCount();
    }
    RoutingUpdate *pp = omnetpp::fromAnyPtr<RoutingUpdate>(object); (void)pp;
    switch (field) {
        case FIELD_senderId: pp->setSenderId((value)); break;
        case FIELD_destination: pp->setDestination((value)); break;
        case FIELD_nextHop: pp->setNextHop((value)); break;
        case FIELD_cost: pp->setCost(string2long(value)); break;
        case FIELD_sequenceNumber: pp->setSequenceNumber(string2long(value)); break;
        case FIELD_hmac: pp->setHmac((value)); break;
        default: throw omnetpp::cRuntimeError("Cannot set field %d of class 'RoutingUpdate'", field);
    }
}

omnetpp::cValue RoutingUpdateDescriptor::getFieldValue(omnetpp::any_ptr object, int field, int i) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldValue(object,field,i);
        field -= base->getFieldCount();
    }
    RoutingUpdate *pp = omnetpp::fromAnyPtr<RoutingUpdate>(object); (void)pp;
    switch (field) {
        case FIELD_senderId: return pp->getSenderId();
        case FIELD_destination: return pp->getDestination();
        case FIELD_nextHop: return pp->getNextHop();
        case FIELD_cost: return pp->getCost();
        case FIELD_sequenceNumber: return (omnetpp::intval_t)(pp->getSequenceNumber());
        case FIELD_hmac: return pp->getHmac();
        default: throw omnetpp::cRuntimeError("Cannot return field %d of class 'RoutingUpdate' as cValue -- field index out of range?", field);
    }
}

void RoutingUpdateDescriptor::setFieldValue(omnetpp::any_ptr object, int field, int i, const omnetpp::cValue& value) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount()){
            base->setFieldValue(object, field, i, value);
            return;
        }
        field -= base->getFieldCount();
    }
    RoutingUpdate *pp = omnetpp::fromAnyPtr<RoutingUpdate>(object); (void)pp;
    switch (field) {
        case FIELD_senderId: pp->setSenderId(value.stringValue()); break;
        case FIELD_destination: pp->setDestination(value.stringValue()); break;
        case FIELD_nextHop: pp->setNextHop(value.stringValue()); break;
        case FIELD_cost: pp->setCost(omnetpp::checked_int_cast<int>(value.intValue())); break;
        case FIELD_sequenceNumber: pp->setSequenceNumber(omnetpp::checked_int_cast<long>(value.intValue())); break;
        case FIELD_hmac: pp->setHmac(value.stringValue()); break;
        default: throw omnetpp::cRuntimeError("Cannot set field %d of class 'RoutingUpdate'", field);
    }
}

const char *RoutingUpdateDescriptor::getFieldStructName(int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldStructName(field);
        field -= base->getFieldCount();
    }
    switch (field) {
        default: return nullptr;
    };
}

omnetpp::any_ptr RoutingUpdateDescriptor::getFieldStructValuePointer(omnetpp::any_ptr object, int field, int i) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldStructValuePointer(object, field, i);
        field -= base->getFieldCount();
    }
    RoutingUpdate *pp = omnetpp::fromAnyPtr<RoutingUpdate>(object); (void)pp;
    switch (field) {
        default: return omnetpp::any_ptr(nullptr);
    }
}

void RoutingUpdateDescriptor::setFieldStructValuePointer(omnetpp::any_ptr object, int field, int i, omnetpp::any_ptr ptr) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount()){
            base->setFieldStructValuePointer(object, field, i, ptr);
            return;
        }
        field -= base->getFieldCount();
    }
    RoutingUpdate *pp = omnetpp::fromAnyPtr<RoutingUpdate>(object); (void)pp;
    switch (field) {
        default: throw omnetpp::cRuntimeError("Cannot set field %d of class 'RoutingUpdate'", field);
    }
}

namespace omnetpp {

}  // namespace omnetpp

