FROM ubuntu:24.04@sha256:72297848456d5d37d1262630108ab308d3e9ec7ed1c3286a32fe09856619a782 AS dependency-build

ENV DEBIAN_FRONTEND=noninteractive
ARG NEEDRESTART_URL=https://codeload.github.com/liske/needrestart/tar.gz/refs/tags/v3.7
ARG NEEDRESTART_SHA256=d801a9f9c9c2f9e10222d7c5dd068d3c9e02390db40b3944d4d0bcabc6c738ad
ARG SCANDEPS_URL=https://cpan.metacpan.org/authors/id/R/RS/RSCHUPP/Module-ScanDeps-1.35.tar.gz
ARG SCANDEPS_SHA256=e5beb3adf55be3dab71f9a1416d4bad57b14e5e05c96370741b9d8f96a51b612

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl && rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN curl -fsSL "${NEEDRESTART_URL}" -o needrestart.tar.gz && \
    echo "${NEEDRESTART_SHA256}  needrestart.tar.gz" | sha256sum -c - && \
    mkdir -p /opt/root-manager/needrestart && \
    tar -xzf needrestart.tar.gz -C /opt/root-manager/needrestart \
        --strip-components=1 && \
    grep -Fq "our \$VERSION = '3.7';" \
        /opt/root-manager/needrestart/perl/lib/NeedRestart.pm

RUN curl -fsSL "${SCANDEPS_URL}" -o scandeps.tar.gz && \
    echo "${SCANDEPS_SHA256}  scandeps.tar.gz" | sha256sum -c - && \
    mkdir scandeps && mkdir -p /opt/root-manager/perl5/Module && \
    tar -xzf scandeps.tar.gz -C scandeps --strip-components=1 && \
    grep -Fq "\$VERSION   = '1.35';" scandeps/lib/Module/ScanDeps.pm && \
    install -m 0444 scandeps/lib/Module/ScanDeps.pm \
        /opt/root-manager/perl5/Module/ScanDeps.pm

FROM ubuntu:24.04@sha256:72297848456d5d37d1262630108ab308d3e9ec7ed1c3286a32fe09856619a782

ENV DEBIAN_FRONTEND=noninteractive
ENV PROB_NAME=root_manager_revenge
ENV PORT=31337

RUN apt-get update && apt-get install -y --no-install-recommends \
    libc6=2.39-0ubuntu8.7 \
    libc-bin=2.39-0ubuntu8.7 \
    perl \
    libintl-perl \
    libmodule-find-perl \
    libproc-processtable-perl \
    libsort-naturally-perl \
    libterm-readkey-perl \
    xinetd \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 1337 ctf && \
    useradd --uid 1337 --gid 1337 --create-home --shell /bin/sh ctf

COPY --from=dependency-build /opt/root-manager /opt/root-manager
COPY root-manager-audit /usr/local/sbin/root-manager-audit
COPY needrestart.conf /etc/root-manager/needrestart.conf
COPY root_manager_revenge /home/ctf/root_manager_revenge
COPY flag /home/ctf/flag
COPY ctf.xinetd /etc/xinetd.d/ctf
COPY xinetd.conf /etc/xinetd.conf

RUN chown -R root:root /opt/root-manager /etc/root-manager && \
    find /opt/root-manager -type d -exec chmod 0555 {} + && \
    find /opt/root-manager -type f -exec chmod 0444 {} + && \
    chmod 0444 /etc/root-manager/needrestart.conf && \
    chown root:root /etc/xinetd.d/ctf /etc/xinetd.conf && \
    chmod 0444 /etc/xinetd.d/ctf /etc/xinetd.conf && \
    chown root:ctf /home/ctf && chmod 0750 /home/ctf && \
    chown root:ctf /home/ctf/root_manager_revenge && \
    chmod 0550 /home/ctf/root_manager_revenge && \
    chown root:root /home/ctf/flag && chmod 0400 /home/ctf/flag && \
    chown root:root /usr/local/sbin/root-manager-audit && \
    chmod 0555 /usr/local/sbin/root-manager-audit && \
    find / -xdev -perm /6000 -type f -exec chmod a-s {} +

EXPOSE 31337
CMD ["/bin/sh", "-c", "/usr/local/sbin/root-manager-audit & exec /usr/sbin/xinetd -dontfork"]
