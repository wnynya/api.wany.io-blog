session=github-actions-wanyne-api-blog
tmux has-session -t $session || tmux new-session -d -s $session
tmux send-keys -t $session C-c
tmux send-keys -t $session "bash" C-m
tmux send-keys -t $session "cd $PWD" C-m
tmux send-keys -t $session "npm run start" C-m