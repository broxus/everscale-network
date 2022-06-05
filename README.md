<p align="center">
    <h3 align="center">everscale-network</h3>
    <p align="center">Everscale network primitives implementation</p>
    <p align="center">
        <a href="/LICENSE">
            <img alt="GitHub" src="https://img.shields.io/github/license/broxus/tiny-adnl" />
        </a>
        <a href="https://github.com/broxus/tiny-adnl/actions?query=workflow%3Amaster">
            <img alt="GitHub Workflow Status" src="https://img.shields.io/github/workflow/status/broxus/tiny-adnl/master" />
        </a>
    </p>
</p>

### Network stack

```text
┌────────────────────────────────┐
│  Network                       │
│          ┌─────────────────────┤
│          │            Overlay  │
├──────────┼──────────┐          │
│    DHT   │   RLDP   │          │
├──────────┴──────────┴──────────┤
│              ADNL              │
├────────────────────────────────┤
│              UDP               │
└────────────────────────────────┘
 ```

### Requirements
- Rust 1.60+
