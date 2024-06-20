#pragma once
#include "../../driver/driver_um_lib.hpp"
#include "../../proc/process.hpp"
#include <locale>
#include <codecvt>
#include <regex>
#include <unordered_map>

namespace dbd {
    inline uint64_t game_base = 0;

    namespace offsets {
        // Global
        constexpr auto OFFSET_GOBJECTS = 0xf1abf00; //latest update
        constexpr auto OFFSET_GWORLD = 0xF34EF50; //latest update
        constexpr auto OFFSET_GNAMES = 0xF0E9640; //latest update
    };
}

struct FVector;
struct FRotator;
struct FName;
template<class T> struct TArray;
struct FString;

struct USceneComponent;
struct UField;
struct UStruct;
struct UClass;
struct UObject;
struct APawn;
struct AActor;
struct ULevel;
struct APlayerState;
struct UPlayer;
struct APlayerController;

struct UGameInstance;
struct AGameStateBase;
struct UWorld;

/*
    Smaller, less important structs that are unlikely to change
*/

enum class EObjectFlags : uint32_t
{
    NoFlags = 0x00000000,

    Public = 0x00000001,
    Standalone = 0x00000002,
    MarkAsNative = 0x00000004,
    Transactional = 0x00000008,
    ClassDefaultObject = 0x00000010,
    ArchetypeObject = 0x00000020,
    Transient = 0x00000040,

    MarkAsRootSet = 0x00000080,
    TagGarbageTemp = 0x00000100,

    NeedInitialization = 0x00000200,
    NeedLoad = 0x00000400,
    KeepForCooker = 0x00000800,
    NeedPostLoad = 0x00001000,
    NeedPostLoadSubobjects = 0x00002000,
    NewerVersionExists = 0x00004000,
    BeginDestroyed = 0x00008000,
    FinishDestroyed = 0x00010000,

    BeingRegenerated = 0x00020000,
    DefaultSubObject = 0x00040000,
    WasLoaded = 0x00080000,
    TextExportTransient = 0x00100000,
    LoadCompleted = 0x00200000,
    InheritableComponentTemplate = 0x00400000,
    DuplicateTransient = 0x00800000,
    StrongRefOnFrame = 0x01000000,
    NonPIEDuplicateTransient = 0x02000000,
    Dynamic = 0x04000000,
    WillBeLoaded = 0x08000000,
};


enum class EClassCastFlags : uint64_t
{
    None = 0x0000000000000000,

    Field = 0x0000000000000001,
    Int8Property = 0x0000000000000002,
    Enum = 0x0000000000000004,
    Struct = 0x0000000000000008,
    ScriptStruct = 0x0000000000000010,
    Class = 0x0000000000000020,
    ByteProperty = 0x0000000000000040,
    IntProperty = 0x0000000000000080,
    FloatProperty = 0x0000000000000100,
    UInt64Property = 0x0000000000000200,
    ClassProperty = 0x0000000000000400,
    UInt32Property = 0x0000000000000800,
    InterfaceProperty = 0x0000000000001000,
    NameProperty = 0x0000000000002000,
    StrProperty = 0x0000000000004000,
    Property = 0x0000000000008000,
    ObjectProperty = 0x0000000000010000,
    BoolProperty = 0x0000000000020000,
    UInt16Property = 0x0000000000040000,
    Function = 0x0000000000080000,
    StructProperty = 0x0000000000100000,
    ArrayProperty = 0x0000000000200000,
    Int64Property = 0x0000000000400000,
    DelegateProperty = 0x0000000000800000,
    NumericProperty = 0x0000000001000000,
    MulticastDelegateProperty = 0x0000000002000000,
    ObjectPropertyBase = 0x0000000004000000,
    WeakObjectProperty = 0x0000000008000000,
    LazyObjectProperty = 0x0000000010000000,
    SoftObjectProperty = 0x0000000020000000,
    TextProperty = 0x0000000040000000,
    Int16Property = 0x0000000080000000,
    DoubleProperty = 0x0000000100000000,
    SoftClassProperty = 0x0000000200000000,
    Package = 0x0000000400000000,
    Level = 0x0000000800000000,
    Actor = 0x0000001000000000,
    PlayerController = 0x0000002000000000,
    Pawn = 0x0000004000000000,
    SceneComponent = 0x0000008000000000,
    PrimitiveComponent = 0x0000010000000000,
    SkinnedMeshComponent = 0x0000020000000000,
    SkeletalMeshComponent = 0x0000040000000000,
    Blueprint = 0x0000080000000000,
    DelegateFunction = 0x0000100000000000,
    StaticMeshComponent = 0x0000200000000000,
    MapProperty = 0x0000400000000000,
    SetProperty = 0x0000800000000000,
    EnumProperty = 0x0001000000000000,
    USparseDelegateFunction = 0x0002000000000000,
    FMulticastInlineDelegateProperty = 0x0004000000000000,
    FMulticastSparseDelegateProperty = 0x0008000000000000,
    FFieldPathProperty = 0x0010000000000000,
    FLargeWorldCoordinatesRealProperty = 0x0080000000000000,
    FOptionalProperty = 0x0100000000000000,
    FVValueProperty = 0x0200000000000000,
    UVerseVMClass = 0x0400000000000000,
    FVRestValueProperty = 0x0800000000000000,
};

struct FVector {
    double x;
    double y;
    double z;
};

struct FRotator {
    double                                        pitch;                                             // 0x0000(0x0008)(Edit, BlueprintVisible, ZeroConstructor, SaveGame, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    double                                        yaw;                                               // 0x0008(0x0008)(Edit, BlueprintVisible, ZeroConstructor, SaveGame, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    double                                        roll;                                              // 0x0010(0x0008)(Edit, BlueprintVisible, ZeroConstructor, SaveGame, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
};

struct FPlane : FVector
{
    double W;
};

struct FMatrix
{
    struct FPlane XPlane;
    struct FPlane YPlane;
    struct FPlane ZPlane;
    struct FPlane WPlane;

    void Print() const {
        // print matrix
        log("%.2f %.2f %.2f %.2f", XPlane.x, XPlane.y, XPlane.z, XPlane.W);
        log("%.2f %.2f %.2f %.2f", YPlane.x, YPlane.y, YPlane.z, YPlane.W);
        log("%.2f %.2f %.2f %.2f", ZPlane.x, ZPlane.y, ZPlane.z, ZPlane.W);
        log("%.2f %.2f %.2f %.2f", WPlane.x, WPlane.y, WPlane.z, WPlane.W);
    }
};


//
//struct FName {
//    int32_t                                         ComparisonIndex;                                   // 0x0000(0x0004)(NOT AUTO-GENERATED PROPERTY)
//    int32_t                                         Number;                                            // 0x0004(0x0004)(NOT AUTO-GENERATED PROPERTY)
//    int32_t                                         DisplayIndex;                                      // 0x0008(0x0004)(NOT AUTO-GENERATED PROPERTY)
//};

struct FNameEntryHandle {
    uint32_t Block = 0;
    uint32_t Offset = 0;

    FNameEntryHandle(uint32_t block, uint32_t offset) : Block(block), Offset(offset) {};
    FNameEntryHandle(uint32_t id) : Block(id >> 16), Offset(id & 65535) {};
    operator uint32_t() const { return (Block << 16 | Offset); }
};

union FStringData final
{
public:
    char                                          AnsiName[0x400];                                   // 0x0000(0x0001)(NOT AUTO-GENERATED PROPERTY)
    wchar_t                                       WideName[0x400];                                   // 0x0000(0x0002)(NOT AUTO-GENERATED PROPERTY)
};

struct FNameEntryHeader final
{
public:
    uint16_t                                        bIsWide : 1;                                       // 0x0000(0x0002)(BitIndex: 0x00, PropSize: 0x0002 (NOT AUTO-GENERATED PROPERTY))
    uint16_t                                        Len : 15;                                          // 0x0000(0x0002)(BitIndex: 0x01, PropSize: 0x0002 (NOT AUTO-GENERATED PROPERTY))
};

struct FNameEntry {
    uint32_t                                      comparison_id;                                        // 0x0000(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
    struct FNameEntryHeader                       Header;                                            // 0x0004(0x0002)(NOT AUTO-GENERATED PROPERTY)
    union FStringData                             Name;                                              // 0x0006(0x0800)(NOT AUTO-GENERATED PROPERTY)

    union
    {
        char AnsiName[1024];
        wchar_t	WideName[1024];
    };

    std::string String() const {
        if (Header.bIsWide) { return std::string(); }

        if (Header.Len > 0)
            return { Name.AnsiName, Header.Len };
        return std::string();
    }
};

struct FNamePool
{
    BYTE Lock[8]; // 0x0
    uint32_t CurrentBlock; // 0x8
    uint32_t CurrentByteCursor; // 0xC
    BYTE* Blocks[8192]; // 0x10

    FNameEntry GetEntry(FNameEntryHandle handle) const
    {
        uint64_t Block = g_proc->read<uint64_t>((void*)(dbd::game_base + dbd::offsets::OFFSET_GNAMES + 0x10 + static_cast<unsigned long long>(handle.Block) * 0x8));
        if(!Block)
            return FNameEntry();

        FNameEntry* entry_ptr = (FNameEntry*)((void*)(Block + uint64_t(handle.Offset * 0x4)));
        if (entry_ptr) {
            FNameEntry entry = g_proc->read<FNameEntry>(entry_ptr);
            return entry;
        }
        return FNameEntry();
    }
};

static std::string get_object_names(int32_t key) {
    uint32_t Chunk = key >> 16;
    USHORT Name = static_cast<USHORT>(key);
    auto FNamePool = dbd::game_base + dbd::offsets::OFFSET_GNAMES; // gnames offset

    std::uintptr_t PtrChunk = g_proc->read<uintptr_t>((void*)(FNamePool + (Chunk + 2) * 8));
    if (!PtrChunk)
        return "";

    std::uintptr_t CurStructName = PtrChunk + (Name * 0x2);
    if (!CurStructName)
        return "";

    USHORT nameLength = g_proc->read<USHORT>((void*)CurStructName) >> 6;

    if (nameLength <= 0)
        return "";

    // Dynamically allocate memory using std::vector
    std::vector<char> buff(nameLength);

    // Read the name into the buffer
    g_proc->read_array(buff.data(), (void*)(CurStructName + 0x2), nameLength);

    std::string name(buff.data(), nameLength);

    // No need to clean up, as std::vector handles memory automatically

    return name;
}

struct FName {
    uint32_t comparison_index; // 0x0
    uint32_t Index; // 0x04
    uint32_t Number; // 0x08

    std::string GetName() const
    {
        FNamePool* fNamePool = (FNamePool*)(dbd::game_base + dbd::offsets::OFFSET_GNAMES);
        FNameEntry entry = fNamePool->GetEntry(comparison_index);
        if (!entry.comparison_id)
            return std::string();

        std::string name = entry.String();

        // This doesn't fucking work???
        if (Index > 0)
            name += '_' + std::to_string(Number);

        uint64_t pos = name.rfind('/');

        if (pos != std::string::npos)
            name = name.substr(pos + 1);

        return name;
    }
};


template<class T>
struct TArray {
private:
    friend struct FString;

public:
    T* Data;
    uint32_t Count;
    uint32_t Max;

    TArray()
    {
        Data = nullptr;
        Max = 0;
        Count = 0;
    }

    int Num() const
    {
        return Count;
    }

    T& operator[](int i)
    {
        return Data[i];
    }

    const T& operator[](int i) const
    {
        return Data[i];
    }

    T* GetData() const {
        return Data;
    }

    bool IsValidIndex(int i) const
    {
        return i < Num();
    }
};

struct FString : TArray<wchar_t>
{
    inline FString()
    {
    };

    FString(const wchar_t* other)
    {
        Max = Count = *other ? (int32_t)std::wcslen(other) + 1 : 0;

        if (Count)
        {
            Data = const_cast<wchar_t*>(other);
        }
    };

    inline bool IsValid() const
    {
        return Data != nullptr;
    }

    inline const wchar_t* c_str() const
    {
        return Data;
    }

    std::string ToString() const
    {
        auto length = std::wcslen(Data);

        std::string str(length, '\0');

        std::use_facet<std::ctype<wchar_t>>(std::locale()).narrow(Data, Data + length, '?', &str[0]);

        return str;
    }
};

/*
    Info structs likely to change
*/

struct FMinimalViewInfo {
    struct FVector                                Location;                                          // 0x0000(0x0018)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    struct FRotator                               Rotation;                                          // 0x0018(0x0018)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, NativeAccessSpecifierPublic)
    float                                         FOV;                                               // 0x0030(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    float                                         DesiredFOV;                                        // 0x0034(0x0004)(ZeroConstructor, Transient, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    float                                         OrthoWidth;                                        // 0x0038(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    float                                         OrthoNearClipPlane;                                // 0x003C(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, Interp, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    float                                         OrthoFarClipPlane;                                 // 0x0040(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, Interp, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    float                                         PerspectiveNearClipPlane;                          // 0x0044(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, Interp, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    float                                         AspectRatio;                                       // 0x0048(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    uint8_t                                       bConstrainAspectRatio : 1;                         // 0x004C(0x0001)(BitIndex: 0x00, PropSize: 0x0001 (Edit, BlueprintVisible, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic))
    uint8_t                                       bUseFieldOfViewForLOD : 1;                         // 0x004C(0x0001)(BitIndex: 0x01, PropSize: 0x0001 (Edit, BlueprintVisible, NoDestructor, AdvancedDisplay, HasGetValueTypeHash, NativeAccessSpecifierPublic))
    uint8_t                                       Pad_CB[0x3];                                       // 0x004D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
    uint8_t                                       ProjectionMode;                                    // 0x0050(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    uint8_t                                       Pad_CC[0x3];                                       // 0x0051(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
    float                                         PostProcessBlendWeight;                            // 0x0054(0x0004)(BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    uint8_t                                       Pad_CD[0x8];                                       // 0x0058(0x0008)(Fixing Size After Last Property [ Dumper-7 ])
    uint8_t                                       PostProcessSettings[0x6E0];                               // 0x0060(0x06E0)(BlueprintVisible, NativeAccessSpecifierPublic)
    uint8_t                                       OffCenterProjectionOffset[0x10];                         // 0x0740(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, Transient, EditConst, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    uint8_t                                       Pad_CE[0x70];                                      // 0x0750(0x0070)(Fixing Struct Size After Last Property [ Dumper-7 ])
};

struct USceneComponent {
    char padding_0[0x140];
    FVector relative_location;
    FRotator relative_rotation;
    FVector relative_scale_3d;
    FVector component_velocity;
};

struct UObject {
    void*                                         VTable;                                            // 0x0000(0x0008)(NOT AUTO-GENERATED PROPERTY)
    EObjectFlags                                  Flags;                                             // 0x0008(0x0004)(NOT AUTO-GENERATED PROPERTY)
    int32_t                                       Index;                                             // 0x000C(0x0004)(NOT AUTO-GENERATED PROPERTY)
    class UClass*                                 Class;                                             // 0x0010(0x0008)(NOT AUTO-GENERATED PROPERTY)
    class FName                                   Name;                                              // 0x0018(0x000C)(NOT AUTO-GENERATED PROPERTY)
    uint8_t                                       Pad_37[0x4];                                       // 0x0024(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
    class UObject*                                Outer;                                             // 0x0028(0x0008)(NOT AUTO-GENERATED PROPERTY)

    inline bool IsA(struct UClass* cmp) const;
    inline std::string GetOuterName(UObject* outer);
    inline std::string GetFullName();
    inline std::string GetName();
    inline uint32_t GetComparisonIndex();
};

struct UField : UObject
{
    struct UField*                                  Next;                                              // 0x0030(0x0008)(NOT AUTO-GENERATED PROPERTY)
};

struct UStruct : UField
{
    uint8_t                                         Pad_3C[0x10];                                      // 0x0038(0x0010)(Fixing Size After Last Property [ Dumper-7 ])
    struct UStruct*                                 Super;                                             // 0x0048(0x0008)(NOT AUTO-GENERATED PROPERTY)
    struct UField*                                  Children;                                          // 0x0050(0x0008)(NOT AUTO-GENERATED PROPERTY)
    struct FField*                                  ChildProperties;                                   // 0x0058(0x0008)(NOT AUTO-GENERATED PROPERTY)
    int32_t                                         Size;                                              // 0x0060(0x0004)(NOT AUTO-GENERATED PROPERTY)
    int32_t                                         MinAlignment;                                      // 0x0064(0x0004)(NOT AUTO-GENERATED PROPERTY)
    uint8_t                                         Pad_3D[0x50];                                      // 0x0068(0x0050)(Fixing Struct Size After Last Property [ Dumper-7 ])
};

struct UClass : UStruct
{
    uint8_t                                         Pad_42[0x28];                                      // 0x00B8(0x0028)(Fixing Size After Last Property [ Dumper-7 ])
    enum struct EClassCastFlags                     CastFlags;                                         // 0x00E0(0x0008)(NOT AUTO-GENERATED PROPERTY)
    uint8_t                                         Pad_43[0x38];                                      // 0x00E8(0x0038)(Fixing Size After Last Property [ Dumper-7 ])
    struct UObject*                                 DefaultObject;                                     // 0x0120(0x0008)(NOT AUTO-GENERATED PROPERTY)
    uint8_t                                         Pad_44[0x108];                                     // 0x0128(0x0108)(Fixing Struct Size After Last Property [ Dumper-7 ])
    

    bool IsSubclassOf(const UStruct* Base) const
    {
        if (!Base)
            return false;

        for (const UStruct* super = (UStruct*)(uint64_t(this)); super; super = g_proc->read<UClass*>((void*)(uint64_t(super) + offsetof(UStruct, Super)))) {
            if (super == Base)
                return true;
        }

        return false;
    }

};

// untested
inline bool UObject::IsA(UClass* cmp) const {
    UClass* super = g_proc->read<UClass*>((void*)(uint64_t(this) + offsetof(UObject, Class)));
    return super->IsSubclassOf(cmp);
}

inline std::string UObject::GetName() {
    FName name = g_proc->read<FName>((void*)(uint64_t(this) + offsetof(UObject, Name)));
    return this ? name.GetName() : "None";
}

inline uint32_t UObject::GetComparisonIndex() {
    FName name = g_proc->read<FName>((void*)(uint64_t(this) + offsetof(UObject, Name)));
    return name.comparison_index;
}

inline std::string UObject::GetOuterName(UObject* outer) {
    if (!outer || uint64_t(outer) > 0x7FFFFFFFFFFF)
        return "";

    std::string outerName = outer->GetName();
    if (outerName.empty() || outerName == "None")
        return "";

    UObject* nextOuter = g_proc->read<UObject*>((void*)(uint64_t(outer) + offsetof(UObject, Outer)));
    std::string nextOuterName = GetOuterName(nextOuter);

    return nextOuterName.empty() ? outerName : outerName + "." + nextOuterName;
}

inline std::string UObject::GetFullName() {
    UClass* class_ptr = (UClass*)(uint64_t(this) + offsetof(UObject, Class));
    std::string Name;

    if (class_ptr)
    {
        UObject* outer = g_proc->read<UObject*>((void*)(uint64_t(this) + offsetof(UObject, Outer)));
        std::string outerName = GetOuterName(outer);

        UClass* cls = g_proc->read<UClass*>(class_ptr);
        std::string Name = cls->GetName() + " " + (outerName.empty() ? this->GetName() : outerName + "." + this->GetName());

        Name = std::regex_replace(Name, std::regex("^ +| +$|( ) +"), "$1"); // Remove leading and trailing spaces...

        return Name;
    }

    return "None";
}
//
//inline std::string UObject::GetFullName() {
//    UClass* class_ptr = (UClass*)(uint64_t(this) + offsetof(UObject, Class));
//    std::string Name;
//
//    if (class_ptr)
//    {
//        std::string Temp;
//        for (UObject* currentOuter = g_proc->read<UObject*>((void*)(uint64_t(this) + offsetof(UObject, Outer))); currentOuter; currentOuter = g_proc->read<UObject*>((void*)(uint64_t(currentOuter) + offsetof(UObject, Outer)))) {
//            if (uint64_t(currentOuter) > 0x7FFFFFFFFFFF)
//                break;
//
//            std::string outerName = currentOuter->GetName();
//            if(!outerName.empty() && outerName != "None")
//                Temp = outerName + "." + Temp;
//        }
//        
//        UClass* cls = g_proc->read<UClass*>(class_ptr);
//        Name = cls->GetName();
//        Name += " ";
//        Name += Temp;
//        Name += this->GetName();
//
//        return Name;
//    }
//
//    return "None";
//}

struct FUObjectItem final
{
public:
    struct UObject* Object;                                            // 0x0000(0x0008)(NOT AUTO-GENERATED PROPERTY)
    uint8_t                                         Pad_0[0x10];                                       // 0x0008(0x0010)(Fixing Struct Size After Last Property [ Dumper-7 ])
};

static std::unordered_map<uint32_t, UObject*> cache;
class TUObjectArray
{
public:
    enum
    {
        ElementsPerChunk = 0x10000,
    };

private:
    static inline auto DecryptPtr = [](void* ObjPtr) -> uint8_t*
        {
            return reinterpret_cast<uint8_t*>(ObjPtr);
        };

public:

    FUObjectItem** Objects;
    BYTE* PreAllocatedObjects;
    uint32_t MaxElements;
    uint32_t NumElements;
    uint32_t MaxChunks;
    uint32_t NumChunks;

public:
    inline int32_t Num() const
    {
        return NumElements;
    }

    inline FUObjectItem** GetDecrytedObjPtr() const
    {
        return reinterpret_cast<FUObjectItem**>(DecryptPtr(Objects));
    }

    bool IsValidIndex(uint32_t Index) const
    {
        return Index < Num() && Index >= 0;
    
    }

    std::vector<UObject*> GetAllObjects() const
    {
        std::vector<UObject*> allObjects;
        allObjects.reserve(MaxElements); // Reserve space for efficiency

        for (uint32_t Index = 0; Index < std::min<uint32_t>(MaxElements, NumChunks * ElementsPerChunk); Index++)
        {
            const uint64_t chunkIndex = Index / ElementsPerChunk;
            const uint32_t withinChunkIndex = Index % ElementsPerChunk;

            FUObjectItem* chunk = g_proc->read<FUObjectItem*>((void*)(Objects + chunkIndex * 0x8));
            if (!chunk)
                continue;

            UObject* item = g_proc->read<UObject*>(chunk + withinChunkIndex);
            if (item)
                allObjects.emplace_back(item);
        }
        return allObjects;
    }

    UObject* GetObjectPtr(uint32_t Index) const
    {
        const uint64_t chunkIndex = Index / ElementsPerChunk;
        const uint32_t withinChunkIndex = Index % ElementsPerChunk;
        if(!IsValidIndex(Index))
            return nullptr;

        if (chunkIndex > NumChunks)
            return nullptr;

        if (Index > MaxElements)
            return nullptr;

        FUObjectItem* chunk = g_proc->read<FUObjectItem*>((void*)(Objects + chunkIndex * 0x8));
        if (!chunk)
            return nullptr;

        UObject* item = g_proc->read<UObject*>(chunk + withinChunkIndex);

        return item;
    }

    void Log() const {
        std::vector objects = GetAllObjects();
        for (const auto& object : objects)
        {
            std::string name = object->GetFullName();
            log("Object: %s", name.c_str());
        }
    }

    inline struct UObject* FindObject(const std::string& name) const
    {
        for (int i = 0; i < NumElements; i++)
        {
            UObject* object = GetObjectPtr(i);

            if (!object)
                continue;

            if (object->GetFullName() == name)
                return object;
        }
        return nullptr;
    }
};

struct UActorComponent : public UObject
{
public:
    uint8_t                                         Pad_36A[0x38];                                      // 0x0030(0x0008)(Fixing Size After Last Property [ Dumper-7 ])
    TArray<class FName>                           ComponentTags;                                     // 0x0068(0x0010)(Edit, BlueprintVisible, ZeroConstructor, NativeAccessSpecifierPublic)
    TArray<class UAssetUserData*>                 AssetUserData;                                     // 0x0078(0x0010)(Edit, ExportObject, ZeroConstructor, ContainsInstancedReference, AdvancedDisplay, Protected, UObjectWrapper, NativeAccessSpecifierProtected)
    uint8_t                                         Pad_36B[0x4];                                      // 0x0088(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
    int32_t                                         UCSSerializationIndex;                             // 0x008C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPrivate)
    uint8_t                                         BitPad_B : 3;                                      // 0x0090(0x0001)(Fixing Bit-Field Size Between Bits [ Dumper-7 ])
    uint8_t                                         bNetAddressable : 1;                               // 0x0090(0x0001)(BitIndex: 0x03, PropSize: 0x0001 (NoDestructor, Protected, HasGetValueTypeHash, NativeAccessSpecifierProtected))
    uint8_t                                         bReplicateUsingRegisteredSubObjectList : 1;        // 0x0090(0x0001)(BitIndex: 0x04, PropSize: 0x0001 (Edit, BlueprintVisible, BlueprintReadOnly, Config, DisableEditOnInstance, NoDestructor, AdvancedDisplay, Protected, HasGetValueTypeHash, NativeAccessSpecifierProtected))
    uint8_t                                         bReplicates : 1;                                   // 0x0090(0x0001)(BitIndex: 0x05, PropSize: 0x0001 (Edit, BlueprintVisible, BlueprintReadOnly, Net, DisableEditOnInstance, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPrivate))
    uint8_t                                         BitPad_C : 2;                                      // 0x0090(0x0001)(Fixing Bit-Field Size For New Byte [ Dumper-7 ])
    uint8_t                                         Pad_36C[0x1];                                      // 0x0091(0x0001)(Fixing Size After Last Property [ Dumper-7 ])
    uint8_t                                         BitPad_D : 1;                                      // 0x0092(0x0001)(Fixing Bit-Field Size Between Bits [ Dumper-7 ])
    uint8_t                                         bAutoActivate : 1;                                 // 0x0092(0x0001)(BitIndex: 0x01, PropSize: 0x0001 (Edit, BlueprintVisible, BlueprintReadOnly, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic))
    uint8_t                                         bIsActive : 1;                                     // 0x0092(0x0001)(BitIndex: 0x02, PropSize: 0x0001 (Net, Transient, RepNotify, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPrivate))
    uint8_t                                         bEditableWhenInherited : 1;                        // 0x0092(0x0001)(BitIndex: 0x03, PropSize: 0x0001 (Edit, DisableEditOnInstance, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic))
    uint8_t                                         BitPad_E : 1;                                      // 0x0092(0x0001)(Fixing Bit-Field Size Between Bits [ Dumper-7 ])
    uint8_t                                         bCanEverAffectNavigation : 1;                      // 0x0092(0x0001)(BitIndex: 0x05, PropSize: 0x0001 (Edit, Config, NoDestructor, AdvancedDisplay, Protected, HasGetValueTypeHash, NativeAccessSpecifierProtected))
    uint8_t                                         BitPad_F : 1;                                      // 0x0092(0x0001)(Fixing Bit-Field Size Between Bits [ Dumper-7 ])
    uint8_t                                         bIsEditorOnly : 1;                                 // 0x0092(0x0001)(BitIndex: 0x07, PropSize: 0x0001 (Edit, BlueprintVisible, BlueprintReadOnly, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic))
    uint8_t                                         Pad_36D[0x2];                                      // 0x0093(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
    uint8_t                                         CreationMethod;                                    // 0x0095(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    uint8_t                                         OnComponentActivated;                              // 0x0096(0x0001)(InstancedReference, BlueprintAssignable, NoDestructor, NativeAccessSpecifierPublic)
    uint8_t                                         OnComponentDeactivated;                            // 0x0097(0x0001)(InstancedReference, BlueprintAssignable, NoDestructor, NativeAccessSpecifierPublic)
    uint8_t                                         Pad_36E[0x10];                                     // 0x0098(0x0010)(Fixing Struct Size After Last Property [ Dumper-7 ])
};

struct AActor : UObject {
    char padding_30[0x120];
    APawn* Owner; // 0x150
    char padding_158[0x38];
    APawn* Instigator; // 0x190
    char padding_1[0x10];
    USceneComponent* RootComponent;
    char padding_1B0[0xC0];
    TArray<class UActorComponent*>                InstanceComponents;
    uint8_t                                         Pad_280[0x20];
};

struct APawn : AActor {
    uint8_t                                         Pad_536[0x8];                                      // 0x02A0(0x0008)(Fixing Size After Last Property [ Dumper-7 ])
    uint8_t                                         bUseControllerRotationPitch : 1;                   // 0x02A8(0x0001)(BitIndex: 0x00, PropSize: 0x0001 (Edit, BlueprintVisible, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic))
    uint8_t                                         bUseControllerRotationYaw : 1;                     // 0x02A8(0x0001)(BitIndex: 0x01, PropSize: 0x0001 (Edit, BlueprintVisible, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic))
    uint8_t                                         bUseControllerRotationRoll : 1;                    // 0x02A8(0x0001)(BitIndex: 0x02, PropSize: 0x0001 (Edit, BlueprintVisible, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic))
    uint8_t                                         bCanAffectNavigationGeneration : 1;                // 0x02A8(0x0001)(BitIndex: 0x03, PropSize: 0x0001 (Edit, BlueprintVisible, BlueprintReadOnly, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic))
    uint8_t                                         BitPad_29 : 2;                                     // 0x02A8(0x0001)(Fixing Bit-Field Size Between Bits [ Dumper-7 ])
    uint8_t                                         bIsLocalViewTarget : 1;                            // 0x02A8(0x0001)(BitIndex: 0x06, PropSize: 0x0001 (Transient, NoDestructor, Protected, HasGetValueTypeHash, NativeAccessSpecifierProtected))
    uint8_t                                         Pad_537[0x3];                                      // 0x02A9(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
    float                                           BaseEyeHeight;                                     // 0x02AC(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    uint8_t                                         AutoPossessPlayer;                                 // 0x02B0(0x0001)(Edit, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    uint8_t                                         AutoPossessAI;                                     // 0x02B1(0x0001)(Edit, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    uint8_t                                         RemoteViewPitch;                                   // 0x02B2(0x0001)(Net, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    uint8_t                                         Pad_538[0x5];                                      // 0x02B3(0x0005)(Fixing Size After Last Property [ Dumper-7 ])
    uint8_t                                         AIControllerClass[0x8];                            // 0x02B8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, NoDestructor, UObjectWrapper, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    class APlayerState*                             PlayerState;                                       // 0x02C0(0x0008)(BlueprintVisible, BlueprintReadOnly, Net, ZeroConstructor, RepNotify, NoDestructor, UObjectWrapper, HasGetValueTypeHash, NativeAccessSpecifierPrivate)
    uint8_t                                         Pad_539[0x8];                                      // 0x02C8(0x0008)(Fixing Size After Last Property [ Dumper-7 ])
    class AController*                              LastHitBy;                                         // 0x02D0(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, NoDestructor, UObjectWrapper, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    class AController*                              Controller;                                        // 0x02D8(0x0008)(Net, ZeroConstructor, RepNotify, NoDestructor, UObjectWrapper, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    class AController*                              PreviousController;                                // 0x02E0(0x0008)(ZeroConstructor, Transient, NoDestructor, UObjectWrapper, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    uint8_t                                         Pad_53A[0x4];                                      // 0x02E8(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
    uint8_t                                         ReceiveControllerChangedDelegate;                  // 0x02EC(0x0001)(InstancedReference, BlueprintAssignable, NoDestructor, NativeAccessSpecifierPublic)
    uint8_t                                         ReceiveRestartedDelegate;                          // 0x02ED(0x0001)(InstancedReference, BlueprintAssignable, NoDestructor, NativeAccessSpecifierPublic)
    uint8_t                                         Pad_53B[0x2];                                      // 0x02EE(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
    struct FVector                                  ControlInputVector;                                // 0x02F0(0x0018)(ZeroConstructor, Transient, IsPlainOldData, NoDestructor, Protected, HasGetValueTypeHash, NativeAccessSpecifierProtected)
    struct FVector                                  LastControlInputVector;                            // 0x0308(0x0018)(ZeroConstructor, Transient, IsPlainOldData, NoDestructor, Protected, HasGetValueTypeHash, NativeAccessSpecifierProtected)
    uint8_t                                         OverrideInputComponentClass[0x8];                  // 0x0320(0x0008)(Edit, ZeroConstructor, DisableEditOnInstance, NoDestructor, Protected, UObjectWrapper, HasGetValueTypeHash, NativeAccessSpecifierProtected)
};

struct ULevel : UObject {
    uint8_t  Pad_38[0x70];
    TArray<struct AActor*> actors;
    char padding_1[0x10];
    UWorld* owning_world;
};

struct APlayerState {
    char padding_0[0x320];
    APawn* PawnPrivate;
    char padding_1[0x78];
    FString PlayerNamePrivate;
};

struct FCameraCacheEntry {
    float time_stamp;
    char padding_1[0xc];
    FMinimalViewInfo pov;
};

struct FTViewTarget final
{
public:
    class AActor*                                   Target;                                            // 0x0000(0x0008)(Edit, BlueprintVisible, ZeroConstructor, NoDestructor, UObjectWrapper, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    uint8_t                                         Pad_169[0x8];                                      // 0x0008(0x0008)(Fixing Size After Last Property [ Dumper-7 ])
    struct FMinimalViewInfo                         POV;                                               // 0x0010(0x07C0)(Edit, BlueprintVisible, NativeAccessSpecifierPublic)
    struct APlayerState*                            PlayerState;                                       // 0x07D0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, NoDestructor, Protected, UObjectWrapper, HasGetValueTypeHash, NativeAccessSpecifierProtected)
    uint8_t                                         Pad_16A[0x8];                                      // 0x07D8(0x0008)(Fixing Struct Size After Last Property [ Dumper-7 ])
};

struct APlayerCameraManager : AActor {
    struct APlayerController*                     PCOwner;                                           // 0x02A0(0x0008)(ZeroConstructor, Transient, NoDestructor, UObjectWrapper, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    struct USceneComponent*                       TransformComponent;                                // 0x02A8(0x0008)(Edit, BlueprintVisible, ExportObject, BlueprintReadOnly, ZeroConstructor, EditConst, InstancedReference, NoDestructor, UObjectWrapper, HasGetValueTypeHash, NativeAccessSpecifierPrivate)
    uint8_t                                         Pad_791[0xC];                                      // 0x02B0(0x000C)(Fixing Size After Last Property [ Dumper-7 ])
    float                                         DefaultFOV;                                        // 0x02BC(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    float                                         LockedFOV;                                      // 0x02C0(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
    float                                         DefaultOrthoWidth;                                 // 0x02C4(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    uint8_t                                         Pad_793[0x4];                                      // 0x02C8(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
    float                                         DefaultAspectRatio;                                // 0x02CC(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    uint8_t                                         Pad_794[0x70];                                     // 0x02D0(0x0070)(Fixing Size After Last Property [ Dumper-7 ])
    struct FCameraCacheEntry                      CameraCache;                                       // 0x0340(0x07D0)(Transient, NativeAccessSpecifierPublic)
    struct FCameraCacheEntry                      LastFrameCameraCache;                              // 0x0B10(0x07D0)(Transient, NativeAccessSpecifierPublic)
    struct FTViewTarget                           ViewTarget;                                        // 0x12E0(0x07E0)(Transient, NativeAccessSpecifierPublic)
    struct FTViewTarget                           PendingViewTarget;                                 // 0x1AC0(0x07E0)(Transient, NativeAccessSpecifierPublic)
    uint8_t                                         Pad_795[0x30];                                   // 0x22A0(0x0030)(Fixing Size After Last Property [ Dumper-7 ])
    struct FCameraCacheEntry                      CameraCachePrivate;                               // 0x22D0(0x07D0)(Transient, NativeAccessSpecifierPrivate)
};

const int a = offsetof(APlayerCameraManager, CameraCachePrivate);

struct AController : AActor
{
    uint8_t                                         Pad_6BD[0x8];                                      // 0x02A0(0x0008)(Fixing Size After Last Property [ Dumper-7 ])
    class APlayerState* PlayerState;                                       // 0x02A8(0x0008)(BlueprintVisible, BlueprintReadOnly, Net, ZeroConstructor, RepNotify, NoDestructor, UObjectWrapper, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    uint8_t                                         Pad_6BE[0x8];                                      // 0x02B0(0x0008)(Fixing Size After Last Property [ Dumper-7 ])
    uint8_t             OnInstigatedAnyDamage[0x10];                             // 0x02B8(0x0010)(ZeroConstructor, InstancedReference, BlueprintAssignable, NativeAccessSpecifierPublic)
    uint8_t             OnPossessedPawnChanged[0x10];                            // 0x02C8(0x0010)(ZeroConstructor, InstancedReference, BlueprintAssignable, NativeAccessSpecifierPublic)
    class FName                                   StateName;                                         // 0x02D8(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    uint8_t                                         Pad_6BF[0x4];                                      // 0x02E4(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
    class APawn* Pawn;                                              // 0x02E8(0x0008)(Net, ZeroConstructor, RepNotify, NoDestructor, UObjectWrapper, HasGetValueTypeHash, NativeAccessSpecifierPrivate)
    uint8_t                                         Pad_6C0[0x8];                                      // 0x02F0(0x0008)(Fixing Size After Last Property [ Dumper-7 ])
    class ACharacter* Character;                                         // 0x02F8(0x0008)(ZeroConstructor, NoDestructor, UObjectWrapper, HasGetValueTypeHash, NativeAccessSpecifierPrivate)
    class USceneComponent* TransformComponent;                                // 0x0300(0x0008)(ExportObject, ZeroConstructor, InstancedReference, NoDestructor, UObjectWrapper, HasGetValueTypeHash, NativeAccessSpecifierPrivate)
    uint8_t                                         Pad_6C1[0x18];                                     // 0x0308(0x0018)(Fixing Size After Last Property [ Dumper-7 ])
    struct FRotator                               ControlRotation;                                   // 0x0320(0x0018)(ZeroConstructor, IsPlainOldData, NoDestructor, Protected, NativeAccessSpecifierProtected)
    uint8_t                                         bAttachToPawn : 1;                                 // 0x0338(0x0001)(BitIndex: 0x00, PropSize: 0x0001 (Edit, DisableEditOnInstance, NoDestructor, Protected, HasGetValueTypeHash, NativeAccessSpecifierProtected))
    uint8_t                                         Pad_6C2[0x7];                                      // 0x0339(0x0007)(Fixing Struct Size After Last Property [ Dumper-7 ])
};

struct APlayerController : AController {
    uint8_t                                         Pad_720[0x8];
    UPlayer* player; 
    APawn* acknowledged_pawn;
    char padding_1[0x8];
    APlayerCameraManager* camera_manager;
};

struct UPlayer : UObject {
    uint8_t            Pad_4C2[0x8];
    APlayerController* player_controller;
};

struct USkillCheck {
    char padding_0[0x151];
    bool is_displayed;
    float current_progress;
    char padding_1[0x4C];
    float bonus_zone;
};

struct UPlayerInteractionHandler {
    char padding_0[0x310];
    USkillCheck* skillcheck;
};

struct ADBDPlayer {
    char padding_0[0xb58];
    UPlayerInteractionHandler* interaction_handler;
};

struct FGameplayTag final
{
public:
    class FName                                   TagName;                                           // 0x0000(0x000C)(Edit, ZeroConstructor, EditConst, SaveGame, IsPlainOldData, NoDestructor, Protected, HasGetValueTypeHash, NativeAccessSpecifierProtected)
};

struct AInteractable : AActor
{
public:
    uint8_t                                         Pad_2C6C[0x68];                                    // 0x02A0(0x0068)(Fixing Size After Last Property [ Dumper-7 ])
    class UPrimitiveComponent* _singleZone;                                       // 0x0308(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, NoDestructor, Protected, HasGetValueTypeHash, NativeAccessSpecifierProtected)
    bool                                          _useSingleZone;                                    // 0x0310(0x0001)(Edit, ZeroConstructor, IsPlainOldData, NoDestructor, Protected, HasGetValueTypeHash, NativeAccessSpecifierProtected)
    uint8_t                                         Pad_2C6D[0x7];                                     // 0x0311(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
    TArray<class UInteractor*>                    _interactors;                                      // 0x0318(0x0010)(ExportObject, ZeroConstructor, Transient, ContainsInstancedReference, Protected, NativeAccessSpecifierProtected)
    class UInteractableTransformOptimizer* _transformOptimizer;                               // 0x0328(0x0008)(Edit, ExportObject, ZeroConstructor, InstancedReference, NoDestructor, Protected, HasGetValueTypeHash, NativeAccessSpecifierProtected)
    uint8_t                                         Pad_2C6E[0x20];                                    // 0x0330(0x0020)(Fixing Size After Last Property [ Dumper-7 ])
    //TMap<class UPrimitiveComponent*, struct FInteractionArray> _zoneToInteractions;                               // 0x0350(0x0050)(Transient, ContainsInstancedReference, NativeAccessSpecifierPrivate)
    uint8_t                                         Pad_2C6E_[0x50];
    class UGameplayTagContainerComponent* _interactableObjectState;                          // 0x03A0(0x0008)(ExportObject, ZeroConstructor, Transient, InstancedReference, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPrivate)
};

struct AGenerator : AInteractable
{
public:
    uint8_t                                         Pad_32E9[0x8];                                     // 0x03A8(0x0008)(Fixing Size After Last Property [ Dumper-7 ])
    bool                                          Activated;                                         // 0x03B0(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    bool                                          WasASMCachePreWarmTriggered;                       // 0x03B1(0x0001)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    bool                                          IsPlaySkillcheckAesthetic;                         // 0x03B2(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    uint8_t                                         Pad_32EA[0x5];                                     // 0x03B3(0x0005)(Fixing Size After Last Property [ Dumper-7 ])
    class UCurveLinearColor* KillerOutlineFadeCurve;                            // 0x03B8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    float                                         NativePercentComplete;                             // 0x03C0(0x0004)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    uint8_t                                         Pad_32EB[0x4];                                     // 0x03C4(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
    uint8_t             OnGeneratorRepaired[0x10];                               // 0x03C8(0x0010)(ZeroConstructor, InstancedReference, BlueprintAssignable, NativeAccessSpecifierPublic)
    uint8_t             OnGeneratorRepairedBySurvivor[0x10];                     // 0x03D8(0x0010)(ZeroConstructor, InstancedReference, BlueprintAssignable, NativeAccessSpecifierPublic)
    uint8_t             OnIsDamagedChanged[0x10];                                // 0x03E8(0x0010)(ZeroConstructor, InstancedReference, BlueprintAssignable, NativeAccessSpecifierPublic)
    uint8_t                                         Pad_32EC[0x48];                                    // 0x03F8(0x0048)(Fixing Size After Last Property [ Dumper-7 ])
    class UGeneratorDamageComponent* _generatorDamageComponent;                         // 0x0440(0x0008)(Edit, BlueprintVisible, ExportObject, BlueprintReadOnly, ZeroConstructor, DisableEditOnInstance, InstancedReference, NoDestructor, Protected, HasGetValueTypeHash, NativeAccessSpecifierProtected)
    bool                                          FireLevelScoreEventOnFix;                          // 0x0448(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, Protected, HasGetValueTypeHash, NativeAccessSpecifierProtected)
    uint8_t                                         Pad_32ED[0x7];                                     // 0x0449(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
    //TMap<class FName, struct FTransform>          _activatedTopLightsTransformMap;                   // 0x0450(0x0050)(Edit, BlueprintVisible, Protected, NativeAccessSpecifierProtected)
    uint8_t                                         Pad_32ED_[0x50];
    class UAIPerceptionStimuliSourceComponent* _perceptionStimuliComponent;                       // 0x04A0(0x0008)(Edit, BlueprintVisible, ExportObject, ZeroConstructor, EditConst, InstancedReference, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPrivate)
    class UDischargeUntilThresholdIsReachedComponent* _regressChargeUntilThresholdIsReached;             // 0x04A8(0x0008)(Edit, ExportObject, ZeroConstructor, DisableEditOnInstance, InstancedReference, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPrivate)
    uint8_t                                         _regressionSpeedWhileDamaged[0x28];                      // 0x04B0(0x0028)(Edit, DisableEditOnInstance, NativeAccessSpecifierPrivate)
    uint8_t                                         Pad_32EE[0x1C];                                    // 0x04D8(0x001C)(Fixing Size After Last Property [ Dumper-7 ])
    struct FGameplayTag                           _repairSemanticTag;                                // 0x04F4(0x000C)(Edit, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPrivate)
    uint8_t                                         Pad_32EF[0x30];                                    // 0x0500(0x0030)(Fixing Size After Last Property [ Dumper-7 ])
    bool                                          _isBlocked;                                        // 0x0530(0x0001)(Net, ZeroConstructor, Transient, IsPlainOldData, RepNotify, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPrivate)
    bool                                          _isBlockedFromCharging;                            // 0x0531(0x0001)(BlueprintVisible, ZeroConstructor, Transient, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPrivate)
    uint8_t                                         Pad_32F0[0x6];                                     // 0x0532(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
    //TSet<class UObject*>                          _blockingSources;                                  // 0x0538(0x0050)(Transient, NativeAccessSpecifierPrivate)
    uint8_t                                         pad_32F0_[0x50];
    uint8_t                                         Pad_32F1[0x30];                                    // 0x0588(0x0030)(Fixing Size After Last Property [ Dumper-7 ])
    class UChargeableComponent* _generatorCharge;                                  // 0x05B8(0x0008)(ExportObject, ZeroConstructor, Transient, InstancedReference, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPrivate)
    TArray<struct FPlayerFloatTuple>              _playerStartTimes;                                 // 0x05C0(0x0010)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, NativeAccessSpecifierPrivate)
    uint8_t                                         Pad_32F2[0x10];                                    // 0x05D0(0x0010)(Fixing Size After Last Property [ Dumper-7 ])
    bool                                          _isAutoCompleted;                                  // 0x05E0(0x0001)(BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPrivate)
    bool                                          _isOvercharged;                                    // 0x05E1(0x0001)(Edit, BlueprintVisible, Net, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPrivate)
    uint8_t                                         Pad_32F3[0x6];                                     // 0x05E2(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
    class UCoopRepairTracker* _coopRepairTracker;                                // 0x05E8(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPrivate)
    uint8_t                                         Pad_32F4[0x14];                                    // 0x05F0(0x0014)(Fixing Size After Last Property [ Dumper-7 ])
    float                                         _VFX_LightDistanceDefault;                         // 0x0604(0x0004)(Edit, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPrivate)
    uint8_t                                         Pad_32F5[0x60];                                    // 0x0608(0x0060)(Fixing Size After Last Property [ Dumper-7 ])
    TArray<class UInteractionDefinition*>         _damagingInteractions;                             // 0x0668(0x0010)(ExportObject, ZeroConstructor, Transient, ContainsInstancedReference, NativeAccessSpecifierPrivate)
    uint8_t                                         Pad_32F6[0x28];                                    // 0x0678(0x0028)(Fixing Size After Last Property [ Dumper-7 ])
    TArray<class ADBDPlayer*>                     _authority_cachedInteractingPlayersOnCompletion;   // 0x06A0(0x0010)(ZeroConstructor, Transient, NativeAccessSpecifierPrivate)
    uint8_t                                         _defaultImmediateRegressionPercentage[0x28];             // 0x06B0(0x0028)(Edit, DisableEditOnInstance, NativeAccessSpecifierPrivate)
    uint8_t                                         Pad_32F7[0x8];                                     // 0x06D8(0x0008)(Fixing Struct Size After Last Property [ Dumper-7 ])
};

struct UBatchMeshCommands : USceneComponent
{
public:
    uint8_t                                         Pad_3D50[0x60];                                    // 0x02C0(0x0060)(Fixing Size After Last Property [ Dumper-7 ])
    TArray<struct FMaterialNamedGroup>            Groups;                                            // 0x0320(0x0010)(Edit, BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Protected, NativeAccessSpecifierProtected)
    TArray<struct FMaterialHelperOriginalMeshState> TargetMeshes;                                      // 0x0330(0x0010)(ZeroConstructor, Transient, Protected, NativeAccessSpecifierProtected)
    class FString                                 _materialGroupName;                                // 0x0340(0x0010)(ZeroConstructor, Transient, HasGetValueTypeHash, NativeAccessSpecifierPrivate)
};

struct UDBDOutlineComponent : UBatchMeshCommands
{
public:
    float                                         InterpolationSpeed;                                // 0x0350(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, Interp, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    bool                                          ShouldBeAboveOutlines;                             // 0x0354(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, Interp, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    bool                                          ForceOutlineFarAway;                               // 0x0355(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, Interp, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    bool                                          LimitToCustomDepthObjects;                         // 0x0356(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, Interp, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    bool                                          FadeOutAsClosingIn;                                // 0x0357(0x0001)(Edit, BlueprintVisible, BlueprintReadOnly, ZeroConstructor, IsPlainOldData, Interp, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    bool                                          IsAlwaysVisible;                                   // 0x0358(0x0001)(Edit, BlueprintVisible, BlueprintReadOnly, ZeroConstructor, IsPlainOldData, Interp, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    uint8_t                                         Pad_31CE[0x3];                                     // 0x0359(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
    float                                         MinimumOutlineDistanceWhenIsAlwaysVisible;         // 0x035C(0x0004)(Edit, BlueprintVisible, BlueprintReadOnly, ZeroConstructor, IsPlainOldData, Interp, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    float                                         MinimumOutlineDistance;                            // 0x0360(0x0004)(Edit, BlueprintVisible, BlueprintReadOnly, ZeroConstructor, IsPlainOldData, Interp, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
    uint8_t                                         Pad_31CF[0x4];                                     // 0x0364(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
    struct FString                                 OutlineName;                                       // 0x0368(0x0010)(Edit, ZeroConstructor, Protected, HasGetValueTypeHash, NativeAccessSpecifierProtected)
    uint8_t                                         Pad_31D0[0x58];                                    // 0x0378(0x0058)(Fixing Size After Last Property [ Dumper-7 ])
    uint8_t      _renderStrategySelector[0x40];                           // 0x03D0(0x0040)(Transient, NativeAccessSpecifierPrivate)
    struct UBatchMeshCommands* _batchMeshCommands;                                // 0x0410(0x0008)(ExportObject, ZeroConstructor, Transient, InstancedReference, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPrivate)
    uint8_t                                         Pad_31D1[0x10];                                    // 0x0418(0x0010)(Fixing Size After Last Property [ Dumper-7 ])
    struct UBaseOutlineRenderStrategy* _renderingStrategy;                                // 0x0428(0x0008)(ZeroConstructor, Transient, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPrivate)
    uint8_t                                         Pad_31D2[0x10];                                    // 0x0430(0x0010)(Fixing Struct Size After Last Property [ Dumper-7 ])
};

/*
    Core structs
*/

struct UGameInstance {
    char padding_0[0x40];
    TArray<UPlayer*> local_players;
};

struct AGameStateBase {
	char padding_0[0x2b8];
    TArray<APlayerState*> player_array;
};

struct FIntVector {
    int x = 0, y = 0;
};

struct UWorld : UObject {
    uint8_t Pad_30[0x8]; // 0x30
    struct ULevel* persistent_level; // 0x38
    uint8_t Pad_40[0x128]; // 0x40
    AGameStateBase* game_state; // 0x168
    char padding_170[0x10]; // 0x170
    TArray<ULevel*> levels; // 0x180
    char padding_2[0x38]; // 0x190
    UGameInstance* owning_game_instance; // 0x1C8
    char padding_1D0[0x4E8];
    double TimeSeconds; // 0x6b8
    double UnpausedTimeSeconds; // 0x6c0
    double RealTimeSeconds; // 0x6c8
    double AudioTimeSeconds; // 0x6d0
    float DeltaRealTimeSeconds; // 0x6d8
    float DeltaTimeSeconds; // 0x6dc
    double PauseDelay; // 0x6e0
    FIntVector OriginLocation; // 0x6e8
};