<h1 align="center"> Adguard CIDRE Sync</h1>

**Adguard CIDRE Sync** - A bot to synchronize adguard clients disallow list with countries CIDR list of your choices.

> [!NOTE]
>_The code was partially written and structured using a generative AI._
>
>_Github repo is a mirror of https://git.djeex.fr/Djeex/adguard-cidre. You'll find full package, history and release note there._

## Sommaire

- [Features](#features)
- [Environment Variables](#environment-variables)
- [Volumes](#volumes)
- [File Structure](#file-structure)
- [Installation and Usage](#installation-and-usage)

## Features

- Downloads CIDR lists by country from GitHub  
- (Optional) Adds manual IPs from a `manually_blocked_ips.conf` file  
- Updates the `AdGuardHome.yaml` file by replacing the `disallowed_clients` list  
- Creates a backup of the original config (`AdGuardHome.yaml.first-start.bak`) on first run  
- Creates a backup before each update (`AdGuardHome.yaml.last-update.bak`)  
- Restarts the AdGuard Home container via Docker API  
- Built-in Python scheduler using the `schedule` library, configurable to run updates daily or weekly  


## Environment Variables


| Variable                 | Description                                                              | Example                     | Possible Values                             |
|--------------------------|--------------------------------------------------------------------------|-----------------------------|---------------------------------------------|
| `TZ`                      | Timezone of the container to correctly schedule updates                | `Europe/Paris`              | Any valid timezone (e.g., `UTC`, `America/New_York`, etc.) |
| `BLOCK_COUNTRIES`         | List of country codes for CIDR lists, separated by commas. You can also define an exclude list (all countries except the specified ones) by prefixing each country code with !. Mixing inclusion and exclusion codes is not supported.                | including list : `cn,ru,ir`, excluding list : `!cn,!ru,!ir`                  | ISO 2-letter country codes                  |
| `BLOCKLIST_CRON_TYPE`     | Scheduling type: `daily` or `weekly`                                    | `daily`                     | `daily`, `weekly`                           |
| `BLOCKLIST_CRON_TIME`     | Time to run update in `HH:MM` 24-hour format                            | `06:00`                     | 24-hour time format                         |
| `BLOCKLIST_CRON_DAY`      | Day of the week for weekly schedule (e.g., `mon`, `tue`, etc.)          | `mon`                       | `mon`, `tue`, `wed`, `thu`, `fri`, `sat`, `sun` |
| `ADGUARD_CONTAINER_NAME`  | Name of the AdGuard Home container to restart                           | `adguardhome`               | Valid Docker container name                 |
| `DOCKER_API_URL`          | Docker API URL (used to restart the container)                          | `http://socket-proxy-adguard:2375` | HTTP URL                                   |

## Volumes

- `/path/to/adguard/confdir` : configuration directory containing `AdGuardHome.yaml` from your adguard container, and optionally `manually_blocked_ips.conf`.

## File Structure

- `blocklist_scheduler.py`: Script to backup, schedule, download CIDRs, merge manual IPs, update config, and restart AdGuard.
- `Dockerfile`: Builds the lightweight python3-slim image.
- `docker-compose.yml`: Example compose file to run the container.
- (optional) `manually_blocked_ips.conf`:  Add extra IPs to block manually.

## Installation and Usage

### With our provided docker image

1. **Create `docker-compose.yml` in your `adguard-cidre` folder**

    ```yaml
    ---
    services:
      adguard-cidre:
        image: git.djeex.fr/djeex/adguard-cidre:latest
        container_name: adguard-cidre
        restart: unless-stopped
        environment:
        - TZ=Europe/Paris # change to your timezone
        - BLOCK_COUNTRIES=cn,ru # choose countries listed IP to block. Full lists here https://github.com/vulnebify/cidre/tree/main/output/cidr/ipv4
        - BLOCKLIST_CRON_TYPE=daily # daily or weekly
      # if weekly, choose the day
      # - BLOCKLIST_CRON_DAY=mon
        - BLOCKLIST_CRON_TIME=06:00
        - DOCKER_API_URL=http://socket-proxy-adguard:2375 # docker socket proxy
        - ADGUARD_CONTAINER_NAME=adguardhome # adguard container name
        volumes:
        - /path/to/adguard/confdir:/adguard

      socket-proxy:
        image: lscr.io/linuxserver/socket-proxy:latest
        container_name: socket-proxy-adguard
        security_opt:
        - no-new-privileges:true
        environment:
        - CONTAINERS=1
        - ALLOW_RESTARTS=1
        volumes:
        - /var/run/docker.sock:/var/run/docker.sock:ro
        restart: unless-stopped
        read_only: true
        tmpfs:
        - /run
    ```
2. **Modify docker-compose.yml**

- Set `BLOCK_COUNTRIES` environment variable with the countries you want to block.
- Adjust `BLOCKLIST_CRON` variables if you want a different update frequency.
- Bind mount your adguard configuration folder (wich contains `AdGuardHome.yaml`) to `/adguard`
- (optionnally) create and edit `manually_blocked_ips.conf` file in your adguard configuration folder to add other IPs you want to block. Only valid IP or CIDR entries will be processed, for exemple :

    ```bash
    192.168.1.100
    10.0.0.0/24
    # Comments or empty lines are ignored
    ```
3. **Start the container**

    ```bash
    docker compose up -d
    ```
    
4. **Check logs to verify updates**

   ```bash
   docker compose logs -f
   ```

### With git (developer)
1. **Clone the repository:**

    ```bash
    git clone https://git.djeex.fr/Djeex/adguard-cidre
    cd adguard-cidre
    ```
2. **Modify docker-compose.yml**

- Set `BLOCK_COUNTRIES` environment variable with the countries you want to block.
- Adjust `BLOCKLIST_CRON` variables if you want a different update frequency.
- Bind mount your adguard configuration folder (wich contains `AdGuardHome.yaml`) to `/adguard`
- (optionnally) create and edit `manually_blocked_ips.conf` file in your adguard configuration folder to add other IPs you want to block. Only valid IP or CIDR entries will be processed, for exemple :

    ```bash
    192.168.1.100
    10.0.0.0/24
    # Comments or empty lines are ignored
    ```

3. **Build and start the container**

    ```bash
    docker compose up -d
    ```
4. **Check logs to verify updates**

   ```bash
   docker compose logs -f
   ```

