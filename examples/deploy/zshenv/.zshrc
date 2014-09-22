source "${HOME}/.zshrc"

if (( $+commands[deploy] )) ; then
  setopt PROMPT_SUBST
  PS1='%{$fg_bold[green]%}$(deploy pm prompt)$fg_bold[blue]%} ➜ %{$reset_color%}'
fi
