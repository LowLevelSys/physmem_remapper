#pragma once
#include "../../driver/driver_um_lib.hpp"
#include "../../proc/process.hpp"


struct FVector;
struct FRotator;
struct FName;
template<class T> struct TArray;
struct FString;

struct USceneComponent;
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

struct FName {
    int comparison_index;
    int Index;
    int Number;
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
    uint32_t ObjectFlags;
    uint32_t InternalIndex;
    struct UClass* ClassPrivate;
    FName NamePrivate;
    UObject* OuterPrivate;
};

struct AActor : UObject {
    char padding_0[0x160];
    APawn* instigator;
    char padding_1[0x10];
    USceneComponent* root_component;
};

struct APawn : AActor {
    char padding_0[0x110];
    APlayerState* player_state;
};

struct ULevel {
    char padding_0[0xA0];
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
    char padding_0[0x22d0];
    FCameraCacheEntry private_camera_cache;
};

struct APlayerController {
    char padding_0[0x348];
    UPlayer* player;
    APawn* acknowledged_pawn;
    char padding_1[0x8];
    APlayerCameraManager* camera_manager;
};

struct UPlayer {
    char padding_0[0x38];
    APlayerController* player_controller;
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

struct UWorld {
	char padding_0[0x168];
    AGameStateBase* game_state;
    char padding_1[0x10];
    TArray<ULevel*> levels;
    char padding_2[0x32];
    UGameInstance* owning_game_instance;
};