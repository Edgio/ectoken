# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|

  config.vm.box = "ubuntu/trusty64"

  # Share an additional folder to the guest VM. The first argument is
  # the path on the host to the actual folder. The second argument is
  # the path on the guest to mount the folder. And the optional third
  # argument is a set of non-required options.
  # config.vm.synced_folder "../data", "/vagrant_data"

  # Cache our dependencies to speed up rebuilds
  if Vagrant.has_plugin?("vagrant-cachier")
    config.cache.scope = :box
  end

  # Provider-specific configuration so you can fine-tune various
  # backing providers for Vagrant. These expose provider-specific options.
  # Example for VirtualBox:
  #
  config.vm.provider "virtualbox" do |vb|
    # Customize the amount of memory on the VM:
    vb.memory = "768"
    vb.cpus = 4
  end

  # View the documentation for the provider you are using for more
  # information on available options.

  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    apt-get upgrade -y
    apt-get autoremove -y
    apt-get install -y apache2 php5-dev python-dev python-pip python-virtualenv build-essential default-jdk mono-complete libssl-dev libffi-dev libbytes-random-secure-perl libcrypt-rijndael-perl libmime-base64-urlsafe-perl
    echo | cpan -i Crypt::GCM || true
    echo | cpan -i Crypt::GCM || true

  SHELL

  config.vm.provision "shell", privileged: false, inline: <<-SHELL
    virtualenv --no-site-packages "$HOME/venv"
    echo 'source "$HOME/venv/bin/activate"' >> "${HOME}/.bashrc"
  SHELL

  config.vm.provision "shell", privileged: false, env: {"VIRTUAL_ENV"=>"$HOME/venv", "PATH"=>"/home/vagrant/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games"}, inline: <<-SHELL
    env
    pip install --upgrade pip
    pip install --upgrade six
    pip install --requirement /vagrant/python-ectoken/requirements.txt
  SHELL
end
