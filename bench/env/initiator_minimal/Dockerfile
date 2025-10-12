FROM archlinux:latest

WORKDIR /app

RUN pacman -Syu --noconfirm \
    base-devel \
    neovim \
    gcc \
    make \
    openssl \
    libinih

#COPY hummingbird .
COPY initiator .

# Compila il progetto
RUN make
CMD tail -f /dev/null
