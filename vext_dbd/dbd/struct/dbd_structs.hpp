#pragma once
#include "../../driver/driver_um_lib.hpp"
#include "../../proc/process.hpp"
#include <locale>
#include <codecvt>

namespace dbd {
    inline uint64_t game_base = 0;

    namespace offsets {
        // Global
        constexpr auto OFFSET_GOBJECTS = 0xF1A9E80;
        constexpr auto OFFSET_GWORLD = 0xf34ce80;
        constexpr auto OFFSET_GNAMES = 0xF0E75C0;
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
    double pitch;
    double yaw;
    double roll;
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

        if (Header.Len <= 512)
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
        uint64_t Block = g_proc->read<uint64_t>((void*)(uint64_t(this) + 0x10 + static_cast<unsigned long long>(handle.Block) * 0x8));
        FNameEntry entry = g_proc->read<FNameEntry>((void*)(Block + static_cast<uint64_t>(4) * handle.Offset));
        return entry;
    }
};

struct FName {
    uint32_t comparison_index; // 0x0
    uint32_t Index; // 0x04
    uint32_t Number; // 0x08

   std::string GetName() const
    {
        FNamePool* fNamePool = (FNamePool*)(dbd::game_base + dbd::offsets::OFFSET_GNAMES);
        FNameEntry entry = fNamePool->GetEntry(comparison_index);

        std::string name = entry.String();

        if (Index > 0 && Number > 0 && comparison_index > 0 && !name.empty())
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
    int32_t Count;
    int32_t Max;

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
    FVector location;
    FRotator rotation;
    float fov;
};

struct USceneComponent {
    char padding_0[0x140];
    FVector relative_location;
    FRotator relative_rotation;
};

struct UObject {
    void** VFTable;
    EObjectFlags Flags;
    uint32_t  Index;
    struct UClass* Class;
    class FName Name;
    uint8_t Pad_37[0x4];
    struct UObject* Outer;

    inline bool IsA(void* cmp) const;
    inline std::string GetFullName();
};

struct UField : UObject
{
    struct UField* Next;                                              // 0x0030(0x0008)(NOT AUTO-GENERATED PROPERTY)
};

struct UStruct : UField
{
    uint8_t                                         Pad_3C[0x10];                                      // 0x0038(0x0010)(Fixing Size After Last Property [ Dumper-7 ])
    struct UStruct* Super;                                             // 0x0048(0x0008)(NOT AUTO-GENERATED PROPERTY)
    struct UField* Children;                                          // 0x0050(0x0008)(NOT AUTO-GENERATED PROPERTY)
    struct FField* ChildProperties;                                   // 0x0058(0x0008)(NOT AUTO-GENERATED PROPERTY)
    int32_t                                         Size;                                              // 0x0060(0x0004)(NOT AUTO-GENERATED PROPERTY)
    int32_t                                         MinAlignemnt;                                      // 0x0064(0x0004)(NOT AUTO-GENERATED PROPERTY)
    uint8_t                                         Pad_3D[0x50];                                      // 0x0068(0x0050)(Fixing Struct Size After Last Property [ Dumper-7 ])
};

struct UClass : UStruct
{
    uint8_t                                         Pad_42[0x28];                                      // 0x00B8(0x0028)(Fixing Size After Last Property [ Dumper-7 ])
    enum struct EClassCastFlags                     CastFlags;                                         // 0x00E0(0x0008)(NOT AUTO-GENERATED PROPERTY)
    uint8_t                                         Pad_43[0x38];                                      // 0x00E8(0x0038)(Fixing Size After Last Property [ Dumper-7 ])
    struct UObject* DefaultObject;                                     // 0x0120(0x0008)(NOT AUTO-GENERATED PROPERTY)
    uint8_t                                         Pad_44[0x108];                                     // 0x0128(0x0108)(Fixing Struct Size After Last Property [ Dumper-7 ])
};

// untested
inline bool UObject::IsA(void* cmp) const {
    for (UClass* super = (UClass*)(uint64_t(this) + offsetof(UObject, Class)); super; super = g_proc->read<UClass*>(super + offsetof(UClass, Super)))
        if (super == cmp) return true; 
    return false;
}

// Semi-Functional?
inline std::string UObject::GetFullName() {
    std::string name;

    // Read outer objects and append their names
    UObject* outer = g_proc->read<UObject*>((void*)(uint64_t(this) + offsetof(UObject, Outer)));
    while (outer) {
        UObject out = g_proc->read<UObject>(outer);
        std::string temp = out.Name.GetName();
        if (!temp.empty() && temp != "None")
            name = temp + "." + name;

        outer = g_proc->read<UObject*>(outer + offsetof(UObject, Outer));
    }

    // Read class name
    UClass cls = g_proc->read<UClass>((void*)(uint64_t(this) + offsetof(UObject, Class)));
    std::string className = cls.Name.GetName();

    // Append class name or original name
    if (!className.empty() && className != "None")
        name = className + " " + name;
    else {
        UObject original = g_proc->read<UObject>((void*)(uint64_t(this)));
        std::string originalName = original.Name.GetName();
        if (!originalName.empty() && originalName != "None")
            name = name + originalName;
    }

    return name;
}

struct FUObjectItem final
{
public:
    struct UObject* Object;                                            // 0x0000(0x0008)(NOT AUTO-GENERATED PROPERTY)
    uint8_t                                         Pad_0[0x10];                                       // 0x0008(0x0010)(Fixing Struct Size After Last Property [ Dumper-7 ])
};

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


    UObject* GetObjectPtr(uint32_t id) const
    {
        if (id >= NumElements) {
            //log("id >= NumElements : %i >= %i", id, NumElements);
            return nullptr;
        }

        uint64_t chunkIndex = id / ElementsPerChunk;
        if (chunkIndex >= NumChunks) {
            //log("chunkIndex >= NumChunks : %i >= %i", chunkIndex, NumChunks);
            return nullptr;
        }

        BYTE* chunk = g_proc->read<BYTE*>(Objects + chunkIndex * 0x8);
        if (!chunk) {
            //log("!chunk");
            return nullptr;
        }

        uint32_t withinChunkIndex = id % ElementsPerChunk * 24;
        UObject* item = g_proc->read<UObject*>(chunk + withinChunkIndex);
        return item;
    }

    inline struct UObject* FindObject(const char* name) const
    {
        for (uint32_t i = 0u; i < NumElements; i++)
        {
            UObject* object = GetObjectPtr(i);
            std::string object_name = object->GetFullName();//GetNameById();

            // debug logging
           /* if(!object_name.empty() && object_name.find("DeadByDaylight") != std::string::npos)
                log("object_name: %s", object_name.c_str());*/

            if (object && object_name == name)
                return object;
        }
        return nullptr;
    }
};

struct AActor : UObject {
    char padding_30[0x120];
    APawn* owner;
    char padding_158[0x38];
    APawn* instigator;
    char padding_1[0x10];
    USceneComponent* root_component;
};

struct APawn : AActor {
    char padding_0[0x110];
    APlayerState* player_state;
};

struct ULevel : UObject {
    uint8_t  Pad_38[0x70];
    TArray<struct AActor*> actors;
    char padding_1[0x10];
    UWorld* owning_world;
};

struct APlayerState {
    char padding_0[0x320];
    APawn* pawn_private;
    char padding_1[0x78];
    FString player_name_private;
};

struct FCameraCacheEntry {
    float time_stamp;
    char padding_1[0xc];
    FMinimalViewInfo pov;
};

struct APlayerCameraManager {
    char padding_0[0x2bc];
    float default_fov;
    float locked_fov;
    char padding_1[0x200c];
    FCameraCacheEntry private_camera_cache;
};

const int a = offsetof(APlayerCameraManager, private_camera_cache);

struct APlayerController {
    char padding_0[0x348];
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

struct UWorld : UObject {
    uint8_t Pad_30[0x8]; 
    struct ULevel* persistent_level;
    uint8_t Pad_40[0x128];
    AGameStateBase* game_state;
    char padding_1[0x10];
    TArray<ULevel*> levels; // 0x180
    char padding_2[0x32];
    UGameInstance* owning_game_instance;
};