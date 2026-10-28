```mermaid
graph TB
    subgraph ASIA_EAST
        PVG01[PVG01<br>Tier: Backbone<br>ConfedAS: 4220241101<br>Underlay: 100.64.11.1<br>LLA: fe80::2024:1:1:5fac/64<br>Public prefix: 2a14:7583:f22d:2000::/56<br>Node IPv6: 2a14:7583:f22d:2000::5fac/128]
        HKG01[HKG01<br>Tier: Node<br>ConfedAS: 4220249102<br>Underlay: 100.64.91.2<br>LLA: fe80::2024:9:1:d576/64<br>Public prefix: 2a14:7583:f224::/48<br>Node IPv6: 2a14:7583:f224::d576/128]
        HKG02[HKG02<br>Tier: Backbone<br>ConfedAS: 4220241103<br>Underlay: 100.64.11.3<br>LLA: fe80::2024:1:1:7d89/64<br>Public prefix: 2a14:7583:f224::/48<br>Node IPv6: 2a14:7583:f224::7d89/128]
        HKG03[HKG03<br>Tier: Backbone<br>ConfedAS: 4220241104<br>Underlay: 100.64.11.4<br>LLA: fe80::2024:1:1:872c/64<br>Public prefix: 2a14:7583:f224::/48<br>Node IPv6: 2a14:7583:f224::872c/128]
        HKG04[HKG04<br>Tier: Backbone<br>ConfedAS: 4220241105<br>Underlay: 100.64.11.5<br>LLA: fe80::2024:1:1:c75a/64<br>Public prefix: 2a14:7583:f224::/48<br>Node IPv6: 2a14:7583:f224::c75a/128]
        TYO01[TYO01<br>Tier: Backbone<br>ConfedAS: 4220241106<br>Underlay: 100.64.11.6<br>LLA: fe80::2024:1:1:63f4/64<br>Public prefix: 2a14:7583:f228::/48<br>Node IPv6: 2a14:7583:f228::63f4/128]
        TYO02[TYO02<br>Tier: Backbone + IX<br>ConfedAS: 4220243107<br>Underlay: 100.64.31.7<br>LLA: fe80::2024:3:1:31c8/64<br>Public prefix: 2a14:7583:f228::/48<br>Node IPv6: 2a14:7583:f228::31c8/128]
        TYO03[TYO03<br>Tier: Backbone<br>ConfedAS: 4220241108<br>Underlay: 100.64.11.8<br>LLA: fe80::2024:1:1:6f78/64<br>Public prefix: 2a14:7583:f228::/48<br>Node IPv6: 2a14:7583:f228::6f78/128]
    end

    subgraph EUROPE
        FRA01[FRA01<br>Tier: Backbone<br>ConfedAS: 4220241201<br>Underlay: 100.64.12.1<br>LLA: fe80::2024:1:2:3b06/64<br>Public prefix: 2a14:7583:f244::/48<br>Node IPv6: 2a14:7583:f244::3b06/128]
        FRA02[FRA02<br>Tier: IX<br>ConfedAS: 4220242202<br>Underlay: 100.64.22.2<br>LLA: fe80::2024:2:2:d131/64<br>Public prefix: 2a14:7583:f244::/48<br>Node IPv6: 2a14:7583:f244::d131/128]
        CDG01[CDG01<br>Tier: Backbone<br>ConfedAS: 4220241203<br>Underlay: 100.64.12.3<br>LLA: fe80::2024:1:2:a024/64<br>Public prefix: 2a14:7583:f244::/48<br>Node IPv6: 2a14:7583:f244::a024/128]
        LHR01[LHR01<br>Tier: Backbone + IX<br>ConfedAS: 4220243204<br>Underlay: 100.64.32.4<br>LLA: fe80::2024:3:2:43af/64<br>Public prefix: 2a14:7583:f244::/48<br>Node IPv6: 2a14:7583:f244::43af/128]
    end

    subgraph NA_WEST
        LAX01[LAX01<br>Tier: Backbone<br>ConfedAS: 4220241401<br>Underlay: 100.64.14.1<br>LLA: fe80::2024:1:4:de75/64<br>Public prefix: 2a14:7583:f284::/48<br>Node IPv6: 2a14:7583:f284::de75/128]
    end

  
    PVG01 <--> HKG04
    PVG01 <--> TYO03
    HKG01 <--> HKG02
    HKG04 <--> HKG02
    HKG04 <--> HKG03
    HKG03 <--> HKG02
    TYO01 <--> HKG02
    HKG02 <--> LAX01
    TYO03 <--> TYO01
    LAX01 <--> FRA01
    FRA01 <--> FRA02
    TYO02 <--> TYO01
    TYO03 <--> TYO02
    LAX01 <--> CDG01
    CDG01 <--> FRA01
    HKG02 <--> CDG01
    TYO01 <--> FRA01
    TYO01 <--> CDG01
    LHR01 <--> CDG01
```

The node values above are derived from the current `node.yml` files and the
addressing filters. In particular, the LLA uses the node token as its final
16-bit field; it is not derived from `node_id`.

Edges represent configured `intra.auto_confed_peers` sessions (WireGuard plus
intra BGP), rather than physical circuits. LHR01 currently has one intra
connection, directly to CDG01.
