graph = {'connect': ['fg-server_outside-in', 'fw-int_outside-in', 'fg-user_outside-in', 'fw-main_inside-in'],
         'fg-server_outside-in': ['fg-server_inside-in', 'connect'],
         'fg-server_inside-in': ['server', 'fg-server_outside-in'],
         'server': ['fg-server_inside-in', '157.249.16.0/23'],
         '157.249.16.0/23': ['server'],
         'fw-int_outside-in': ['connect', 'fw-int_inside-in'],
         'fw-int_inside-in': ['fw-int_outside-in', 'int'],
         'int': ['fw-int_inside-in', '157.249.90.0/24', '157.249.20.0/24', '157.249.66.0/24'],
         '157.249.90.0/24': ['int'],
         '157.249.20.0/24': ['int'],
         '157.249.66.0/24': ['int'],
         'fg-user_outside-in': ['connect', 'fg-user_inside-in'],
         'fg-user_inside-in': ['fg-user_outside-in', 'user'], 
         'user': ['fg-user_inside-in', '157.249.112.0/21'],
         '157.249.112.0/21': ['user'],
         'fw-main_inside-in': ['connect', 'fw-main_outside-in'],
         'fw-main_outside-in': ['fw-main_inside_in', 'outside'],
         'outside': ['fw-main_outside-in', 'fg-maindmz_outside-in', 'internet'],
         'fg-maindmz_outside-in': ['fg-maindmz_inside-in', 'outside'],
         'fg-maindmz_inside-in': ['fg-maindmz_outside-in', 'maindmz'],
         'maindmz': ['fg-maindmz_inside-in', '157.249.32.0/24'],
         '157.249.32.0/24': ['maindmz']}
